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
from typing import TypeAlias

from oslo_policy import _checks

LOG = logging.getLogger(__name__)

TokenT: TypeAlias = str
ValueT: TypeAlias = str | _checks.BaseCheck
ReductionResultT: TypeAlias = list[tuple[TokenT, ValueT]]


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
        self.tokens: list[TokenT] = []
        self.values: list[ValueT] = []

    def reduce(self) -> None:
        """Perform a greedy reduction of the token stream.

        Uses pattern matching to efficiently find and apply reduction rules.
        If a rule matches, it will be executed, then the method will be called
        recursively to search for any more possible reductions.
        """
        # Try 3-token patterns first
        if len(self.tokens) >= 3:
            match self.tokens[-3:]:
                # Parenthesized expressions
                case (
                    ['(', 'check', ')']
                    | ['(', 'and_expr', ')']
                    | ['(', 'or_expr', ')']
                ):
                    results = self._wrap_check(*self.values[-3:])
                    self.tokens[-3:] = [r[0] for r in results]
                    self.values[-3:] = [r[1] for r in results]
                    return self.reduce()

                # AND expressions
                case ['check', 'and', 'check']:
                    results = self._make_and_expr(*self.values[-3:])
                    self.tokens[-3:] = [r[0] for r in results]
                    self.values[-3:] = [r[1] for r in results]
                    return self.reduce()

                case ['and_expr', 'and', 'check']:
                    results = self._extend_and_expr(*self.values[-3:])
                    self.tokens[-3:] = [r[0] for r in results]
                    self.values[-3:] = [r[1] for r in results]
                    return self.reduce()

                case ['or_expr', 'and', 'check']:
                    results = self._mix_or_and_expr(*self.values[-3:])
                    self.tokens[-3:] = [r[0] for r in results]
                    self.values[-3:] = [r[1] for r in results]
                    return self.reduce()

                # OR expressions
                case ['check', 'or', 'check'] | ['and_expr', 'or', 'check']:
                    results = self._make_or_expr(*self.values[-3:])
                    self.tokens[-3:] = [r[0] for r in results]
                    self.values[-3:] = [r[1] for r in results]
                    return self.reduce()

                case ['or_expr', 'or', 'check']:
                    results = self._extend_or_expr(*self.values[-3:])
                    self.tokens[-3:] = [r[0] for r in results]
                    self.values[-3:] = [r[1] for r in results]
                    return self.reduce()

        # Try 2-token patterns
        if len(self.tokens) >= 2:
            match self.tokens[-2:]:
                # NOT expressions
                case ['not', 'check']:
                    results = self._make_not_expr(*self.values[-2:])
                    self.tokens[-2:] = [r[0] for r in results]
                    self.values[-2:] = [r[1] for r in results]
                    return self.reduce()

    def shift(self, tok: TokenT, value: ValueT) -> None:
        """Adds one more token to the state.

        Calls :meth:`reduce`.
        """
        self.tokens.append(tok)
        self.values.append(value)

        # Do a greedy reduce...
        self.reduce()

    @property
    def result(self) -> _checks.BaseCheck:
        """Obtain the final result of the parse.

        :raises ValueError: If the parse failed to reduce to a single result.
        """
        if len(self.values) != 1:
            raise ValueError('Could not parse rule')

        value = self.values[0]
        if not isinstance(value, _checks.BaseCheck):
            raise ValueError('Could not parse rule')

        return value

    def _wrap_check(
        self, _p1: str, check: _checks.BaseCheck, _p2: str
    ) -> ReductionResultT:
        """Turn parenthesized expressions into a 'check' token."""
        return [('check', check)]

    def _make_and_expr(
        self, check1: _checks.BaseCheck, _and: str, check2: _checks.BaseCheck
    ) -> ReductionResultT:
        """Create an 'and_expr'.

        Join two checks by the 'and' operator.
        """
        return [('and_expr', _checks.AndCheck([check1, check2]))]

    def _mix_or_and_expr(
        self, or_expr: _checks.OrCheck, _and: str, check: _checks.BaseCheck
    ) -> ReductionResultT:
        """Modify the case 'A or B and C'"""
        or_expr, check1 = or_expr.pop_check()
        if isinstance(check1, _checks.AndCheck):
            and_expr = check1.add_check(check)
        else:
            and_expr = _checks.AndCheck([check1, check])
        return [('or_expr', or_expr.add_check(and_expr))]

    def _extend_and_expr(
        self, and_expr: _checks.AndCheck, _and: str, check: _checks.BaseCheck
    ) -> ReductionResultT:
        """Extend an 'and_expr' by adding one more check."""
        return [('and_expr', and_expr.add_check(check))]

    def _make_or_expr(
        self, check1: _checks.BaseCheck, _or: str, check2: _checks.BaseCheck
    ) -> ReductionResultT:
        """Create an 'or_expr'.

        Join two checks by the 'or' operator.
        """
        return [('or_expr', _checks.OrCheck([check1, check2]))]

    def _extend_or_expr(
        self, or_expr: _checks.OrCheck, _or: str, check: _checks.BaseCheck
    ) -> ReductionResultT:
        """Extend an 'or_expr' by adding one more check."""
        return [('or_expr', or_expr.add_check(check))]

    def _make_not_expr(
        self, _not: str, check: _checks.BaseCheck
    ) -> ReductionResultT:
        """Invert the result of another check."""
        return [('check', _checks.NotCheck(check))]


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


def _parse_tokenize(rule: str) -> Generator[tuple[TokenT, ValueT], None, None]:
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
            yield '(', '('

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
            # Special tokens
            yield lowered, clean
        elif clean:
            # Not a special token, but not composed solely of ')'
            if len(tok) >= 2 and (
                (tok[0], tok[-1]) in [('"', '"'), ("'", "'")]
            ):
                # It's a quoted string
                yield 'string', tok[1:-1]
            else:
                yield 'check', _parse_check(clean)

        # Yield the trailing parens
        for i in range(trail):
            yield ')', ')'


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
    for tok, value in _parse_tokenize(rule):
        state.shift(tok, value)

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
