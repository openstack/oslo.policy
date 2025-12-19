#
# Copyright (c) 2015 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import re
from collections.abc import Generator, Sequence
from typing import Any, Generic, TypeAlias, TypeVar

from oslo_policy import _checks

LOG = logging.getLogger(__name__)

T = TypeVar('T')
TokenT: TypeAlias = str
ValueT: TypeAlias = str | _checks.BaseCheck


class Token(Generic[T]):
    def __init__(self, value: T) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f'<{self.__class__.__qualname__}({self.value})'

    def __eq__(self, other: Any) -> bool:
        return type(self) is type(other) and self.value == other.value


# fmt: off
class CheckToken(Token[_checks.BaseCheck]): ...
class AndExprToken(Token[_checks.AndCheck]): ...
class OrExprToken(Token[_checks.OrCheck]): ...
class AndToken(Token[str]): ...
class OrToken(Token[str]): ...
class NotToken(Token[str]): ...
class LeftParamToken(Token[str]): ...
class RightParamToken(Token[str]): ...
class StringToken(Token[str]): ...
# fmt: on


class ParseState:
    """Implement the core of parsing the policy language.

    Uses a greedy reduction algorithm to reduce a sequence of tokens into
    a single terminal, the value of which will be the root of the
    :class:`Check` tree.

    .. note::

        Error reporting is rather lacking.  The best we can get with this
        parser formulation is an overall "parse failed" error. Fortunately, the
        policy language is simple enough that this shouldn't be that big a
        problem.
    """

    def __init__(self) -> None:
        """Initialize the ParseState."""
        self.stack: list[Token[Any]] = []

    def reduce(self) -> None:
        """Perform a greedy reduction of the token stream.

        Uses pattern matching to efficiently find and apply reduction rules.
        If a rule matches, it will be executed, then the method will be called
        recursively to search for any more possible reductions.
        """
        # Try 3-token patterns first
        if len(self.stack) >= 3:
            token_a, token_b, token_c = self.stack[-3:]
            match [token_a, token_b, token_c]:
                # Parenthesized expressions
                case (
                    [LeftParamToken(), CheckToken(), RightParamToken()]
                    | [LeftParamToken(), AndExprToken(), RightParamToken()]
                    | [LeftParamToken(), OrExprToken(), RightParamToken()]
                ):
                    # Turn parenthesized expressions into a 'check' token
                    self.stack[-3:] = [CheckToken(token_b.value)]
                    return self.reduce()

                # AND expressions
                case [CheckToken(), AndToken(), CheckToken()]:
                    # Create an 'and_expr' - join two checks by the 'and'
                    # operator
                    check1, check2 = token_a.value, token_c.value
                    and_check = _checks.AndCheck([check1, check2])
                    self.stack[-3:] = [AndExprToken(and_check)]
                    return self.reduce()

                case [AndExprToken(), AndToken(), CheckToken()]:
                    # Extend an 'and_expr' by adding one more check
                    and_expr, check = token_a.value, token_c.value
                    extended_and = and_expr.add_check(check)
                    self.stack[-3:] = [AndExprToken(extended_and)]
                    return self.reduce()

                case [OrExprToken(), AndToken(), CheckToken()]:
                    # Modify the case 'A or B and C'
                    or_expr, check = token_a.value, token_c.value
                    or_expr_check, check1 = or_expr.pop_check()
                    if isinstance(check1, _checks.AndCheck):
                        and_expr = check1.add_check(check)
                    else:
                        and_expr = _checks.AndCheck([check1, check])
                    result_or = or_expr_check.add_check(and_expr)
                    self.stack[-3:] = [OrExprToken(result_or)]
                    return self.reduce()

                # OR expressions
                case [CheckToken(), OrToken(), CheckToken()] | [
                    AndExprToken(),
                    OrToken(),
                    CheckToken(),
                ]:
                    # Create an 'or_expr' - join two checks by the 'or'
                    # operator
                    check1, check2 = token_a.value, token_c.value
                    or_check = _checks.OrCheck([check1, check2])
                    self.stack[-3:] = [OrExprToken(or_check)]
                    return self.reduce()

                case [OrExprToken(), OrToken(), CheckToken()]:
                    # Extend an 'or_expr' by adding one more check
                    or_expr, check = token_a.value, token_c.value
                    extended_or = or_expr.add_check(check)
                    self.stack[-3:] = [OrExprToken(extended_or)]
                    return self.reduce()

        # Try 2-token patterns
        if len(self.stack) >= 2:
            token_a, token_b = self.stack[-2:]
            match self.stack[-2:]:
                # NOT expressions
                case [NotToken(), CheckToken()]:
                    # Invert the result of another check
                    check = token_b.value
                    not_check = _checks.NotCheck(check)
                    self.stack[-2:] = [CheckToken(not_check)]
                    return self.reduce()

    def shift(self, token: Token[Any]) -> None:
        """Adds one more token to the state.

        Calls :meth:`reduce`.
        """
        self.stack.append(token)

        # Do a greedy reduce...
        self.reduce()

    @property
    def result(self) -> _checks.BaseCheck:
        """Obtain the final result of the parse.

        :raises ValueError: If the parse failed to reduce to a single result.
        """
        if len(self.stack) != 1:
            raise ValueError('Could not parse rule')

        value = self.stack[0].value
        if not isinstance(value, _checks.BaseCheck):
            # we should never get here since we should have reduced out any
            # string tokens
            raise ValueError('Could not parse rule')

        return value


def _parse_check(rule: str) -> _checks.BaseCheck:
    """Parse a single base check rule into an appropriate Check object."""
    # Handle the special checks
    if rule == '!':
        return _checks.FalseCheck()
    elif rule == '@':
        return _checks.TrueCheck()

    try:
        kind, match = rule.split(':', 1)
    except Exception:
        LOG.exception('Failed to understand rule %s', rule)
        # If the rule is invalid, we'll fail closed
        return _checks.FalseCheck()

    # Find what implements the check
    extension_checks = _checks.get_extensions()
    if kind in extension_checks:
        return extension_checks[kind](kind, match)
    elif kind in _checks.registered_checks:
        return _checks.registered_checks[kind](kind, match)
    elif None in _checks.registered_checks:
        return _checks.registered_checks[None](kind, match)
    else:
        LOG.error('No handler for matches of kind %s', kind)
        return _checks.FalseCheck()


def _parse_list_rule(rule: Sequence[str | Sequence[str]]) -> _checks.BaseCheck:
    """Translates the old list-of-lists syntax into a tree of Check objects.

    Provided for backwards compatibility.
    """
    # Empty rule defaults to True
    if not rule:
        return _checks.TrueCheck()

    # Outer list is joined by "or"; inner list by "and"
    or_list: list[_checks.BaseCheck] = []
    for inner_rule in rule:
        # Skip empty inner lists
        if not inner_rule:
            continue

        # Handle bare strings
        if isinstance(inner_rule, str):
            inner_rule = [inner_rule]

        # Parse the inner rules into Check objects
        and_list = [_parse_check(r) for r in inner_rule]

        # Append the appropriate check to the or_list
        if len(and_list) == 1:
            or_list.append(and_list[0])
        else:
            or_list.append(_checks.AndCheck(and_list))

    # If we have only one check, omit the "or"
    if not or_list:
        return _checks.FalseCheck()
    elif len(or_list) == 1:
        return or_list[0]

    return _checks.OrCheck(or_list)


# Used for tokenizing the policy language
_tokenize_re = re.compile(r'\s+')


def _parse_tokenize(rule: str) -> Generator[Token[Any], None, None]:
    """Tokenizer for the policy language.

    Most of the single-character tokens are specified in the
    ``_tokenize_re``; however, parentheses need to be handled specially,
    because they can appear inside a check string.  Thankfully, those
    parentheses that appear inside a check string can never occur at
    the very beginning or end (``"%(variable)s"`` is the correct syntax).
    """
    for tok in _tokenize_re.split(rule):
        # Skip empty tokens
        if not tok or tok.isspace():
            continue

        # Handle leading parens on the token
        clean = tok.lstrip('(')
        for i in range(len(tok) - len(clean)):
            # yes, the value argument is redundant but meh
            yield LeftParamToken('(')

        # If it was only parentheses, continue
        if not clean:
            continue
        else:
            tok = clean

        # Handle trailing parens on the token
        clean = tok.rstrip(')')
        trail = len(tok) - len(clean)

        # Yield the cleaned token
        lowered = clean.lower()
        if lowered in ('and', 'or', 'not'):
            match lowered:
                case 'and':
                    yield AndToken(clean)
                case 'or':
                    yield OrToken(clean)
                case 'not':
                    yield NotToken(clean)
        elif clean:
            # Not a special token, but not composed solely of ')'
            if len(tok) >= 2 and (
                (tok[0], tok[-1]) in [('"', '"'), ("'", "'")]
            ):
                # It's a quoted string: drop the quotes
                yield StringToken(tok[1:-1])
            else:
                yield CheckToken(_parse_check(clean))

        # Yield the trailing parens
        for i in range(trail):
            yield RightParamToken(')')


def _parse_text_rule(rule: str) -> _checks.BaseCheck:
    """Parses policy to the tree.

    Translates a policy written in the policy language into a tree of
    Check objects.
    """
    # Empty rule means always accept
    if not rule:
        return _checks.TrueCheck()

    # Parse the token stream
    state = ParseState()
    for token in _parse_tokenize(rule):
        state.shift(token)

    try:
        return state.result
    except ValueError:
        # Couldn't parse the rule
        LOG.exception('Failed to understand rule %s', rule)

        # Fail closed
        return _checks.FalseCheck()


def parse_rule(rule: str | Sequence[str | Sequence[str]]) -> _checks.BaseCheck:
    """Parses a policy rule into a tree of :class:`.Check` objects."""
    # If the rule is a string, it's in the policy language
    if isinstance(rule, str):
        return _parse_text_rule(rule)
    return _parse_list_rule(rule)
