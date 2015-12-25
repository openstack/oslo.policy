# -*- coding: utf-8 -*-
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

import abc
import ast
import contextlib
import copy

from oslo_serialization import jsonutils
import requests
import six


registered_checks = {}


@six.add_metaclass(abc.ABCMeta)
class BaseCheck(object):
    """Abstract base class for Check classes."""

    @abc.abstractmethod
    def __str__(self):
        """String representation of the Check tree rooted at this node."""

        pass

    @abc.abstractmethod
    def __call__(self, target, cred, enforcer):
        """Triggers if instance of the class is called.

        Performs the check. Returns False to reject the access or a
        true value (not necessary True) to accept the access.
        """

        pass


class FalseCheck(BaseCheck):
    """A policy check that always returns ``False`` (disallow)."""

    def __str__(self):
        """Return a string representation of this check."""

        return '!'

    def __call__(self, target, cred, enforcer):
        """Check the policy."""

        return False


class TrueCheck(BaseCheck):
    """A policy check that always returns ``True`` (allow)."""

    def __str__(self):
        """Return a string representation of this check."""

        return '@'

    def __call__(self, target, cred, enforcer):
        """Check the policy."""

        return True


class Check(BaseCheck):
    def __init__(self, kind, match):
        self.kind = kind
        self.match = match

    def __str__(self):
        """Return a string representation of this check."""

        return '%s:%s' % (self.kind, self.match)


class NotCheck(BaseCheck):
    def __init__(self, rule):
        self.rule = rule

    def __str__(self):
        """Return a string representation of this check."""

        return 'not %s' % self.rule

    def __call__(self, target, cred, enforcer):
        """Check the policy.

        Returns the logical inverse of the wrapped check.
        """

        return not self.rule(target, cred, enforcer)


class AndCheck(BaseCheck):
    def __init__(self, rules):
        self.rules = rules

    def __str__(self):
        """Return a string representation of this check."""

        return '(%s)' % ' and '.join(str(r) for r in self.rules)

    def __call__(self, target, cred, enforcer):
        """Check the policy.

        Requires that all rules accept in order to return True.
        """

        for rule in self.rules:
            if not rule(target, cred, enforcer):
                return False

        return True

    def add_check(self, rule):
        """Adds rule to be tested.

        Allows addition of another rule to the list of rules that will
        be tested.

        :returns: self
        :rtype: :class:`.AndCheck`
        """

        self.rules.append(rule)
        return self


class OrCheck(BaseCheck):
    def __init__(self, rules):
        self.rules = rules

    def __str__(self):
        """Return a string representation of this check."""

        return '(%s)' % ' or '.join(str(r) for r in self.rules)

    def __call__(self, target, cred, enforcer):
        """Check the policy.

        Requires that at least one rule accept in order to return True.
        """

        for rule in self.rules:
            if rule(target, cred, enforcer):
                return True
        return False

    def add_check(self, rule):
        """Adds rule to be tested.

        Allows addition of another rule to the list of rules that will
        be tested.  Returns the OrCheck object for convenience.
        """

        self.rules.append(rule)
        return self

    def pop_check(self):
        """Pops the last check from the list and returns them

        :returns: self, the popped check
        :rtype: :class:`.OrCheck`, class:`.Check`
        """

        check = self.rules.pop()
        return self, check


def register(name, func=None):
    # Perform the actual decoration by registering the function or
    # class.  Returns the function or class for compliance with the
    # decorator interface.
    def decorator(func):
        registered_checks[name] = func
        return func

    # If the function or class is given, do the registration
    if func:
        return decorator(func)

    return decorator


@register('rule')
class RuleCheck(Check):
    def __call__(self, target, creds, enforcer):
        try:
            return enforcer.rules[self.match](target, creds, enforcer)
        except KeyError:
            # We don't have any matching rule; fail closed
            return False


@register('role')
class RoleCheck(Check):
    """Check that there is a matching role in the ``creds`` dict."""

    def __call__(self, target, creds, enforcer):
        try:
            match = self.match % target
        except KeyError:
            # While doing RoleCheck if key not
            # present in Target return false
            return False
        if 'roles' in creds:
            return match.lower() in [x.lower() for x in creds['roles']]
        return False


@register('http')
class HttpCheck(Check):
    """Check ``http:`` rules by calling to a remote server.

    This example implementation simply verifies that the response
    is exactly ``True``.
    """

    def __call__(self, target, creds, enforcer):
        url = ('http:' + self.match) % target

        # Convert instances of object() in target temporarily to
        # empty dict to avoid circular reference detection
        # errors in jsonutils.dumps().
        temp_target = copy.deepcopy(target)
        for key in target.keys():
            element = target.get(key)
            if type(element) is object:
                temp_target[key] = {}
        data = {'target': jsonutils.dumps(temp_target),
                'credentials': jsonutils.dumps(creds)}
        with contextlib.closing(requests.post(url, data=data)) as r:
            return r.text == 'True'


@register(None)
class GenericCheck(Check):
    """Check an individual match.

    Matches look like:

        - tenant:%(tenant_id)s
        - role:compute:admin
        - True:%(user.enabled)s
        - 'Member':%(role.name)s
    """

    def _find_in_dict(self, test_value, path_segments, match):
        '''Searches for a match in the dictionary.

        test_value is a reference inside the dictionary. Since the process is
        recursive, each call to _find_in_dict will be one level deeper.

        path_segments is the segments of the path to search.  The recursion
        ends when there are no more segments of path.

        When specifying a value inside a list, each element of the list is
        checked for a match. If the value is found within any of the sub lists
        the check succeeds; The check only fails if the entry is not in any of
        the sublists.

        '''

        if len(path_segments) == 0:
            return match == six.text_type(test_value)
        key, path_segments = path_segments[0], path_segments[1:]
        try:
            test_value = test_value[key]
        except KeyError:
            return False
        if isinstance(test_value, list):
            for val in test_value:
                if self._find_in_dict(val, path_segments, match):
                    return True
            return False
        else:
            return self._find_in_dict(test_value, path_segments, match)

    def __call__(self, target, creds, enforcer):

        try:
            match = self.match % target
        except KeyError:
            # While doing GenericCheck if key not
            # present in Target return false
            return False
        try:
            # Try to interpret self.kind as a literal
            test_value = ast.literal_eval(self.kind)
            return match == six.text_type(test_value)

        except ValueError:
            pass

        path_segments = self.kind.split('.')
        return self._find_in_dict(creds, path_segments, match)
