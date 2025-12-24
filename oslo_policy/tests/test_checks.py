# Copyright (c) 2015 OpenStack Foundation.
# All Rights Reserved.

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

from typing import Any
from unittest import mock

from oslotest import base as test_base

from oslo_policy import _checks
from oslo_policy import policy
from oslo_policy.tests import base
from oslo_policy.tests import token_fixture


class CheckRegisterTestCase(test_base.BaseTestCase):
    @mock.patch.object(_checks, 'registered_checks', {})
    def test_register_check(self):
        class TestCheck(_checks.Check):
            pass

        _checks.register('spam', TestCheck)

        self.assertEqual({'spam': TestCheck}, _checks.registered_checks)

    @mock.patch.object(_checks, 'registered_checks', {})
    def test_register_check_decorator(self):
        @_checks.register('spam')
        class TestCheck(_checks.Check):
            pass

        self.assertEqual({'spam': TestCheck}, _checks.registered_checks)


class RuleCheckTestCase(base.PolicyBaseTestCase):
    def test_rule_missing(self):
        self.enforcer.rules = policy.Rules({})
        check = _checks.RuleCheck('rule', 'spam')

        self.assertFalse(check({}, {}, self.enforcer))

    def test_rule_false(self):
        self.enforcer.rules = policy.Rules({'spam': _BoolCheck(False)})
        check = _checks.RuleCheck('rule', 'spam')

        self.assertFalse(check({}, {}, self.enforcer))

    def test_rule_true(self):
        self.enforcer.rules = policy.Rules({'spam': _BoolCheck(True)})
        check = _checks.RuleCheck('rule', 'spam')

        self.assertTrue(check({}, {}, self.enforcer))


class RoleCheckTestCase(base.PolicyBaseTestCase):
    def test_accept(self):
        check = _checks.RoleCheck('role', 'sPaM')

        self.assertTrue(check({}, {'roles': ['SpAm']}, self.enforcer))

    def test_reject(self):
        check = _checks.RoleCheck('role', 'spam')

        self.assertFalse(check({}, {'roles': []}, self.enforcer))

    def test_format_value(self):
        check = _checks.RoleCheck('role', '%(target.role.name)s')

        target_dict: dict[str, Any] = {'target.role.name': 'a'}
        cred_dict = {'user': 'user', 'roles': ['a', 'b', 'c']}
        self.assertTrue(check(target_dict, cred_dict, self.enforcer))

        target_dict = {'target.role.name': 'd'}
        self.assertFalse(check(target_dict, cred_dict, self.enforcer))

        target_dict = {'target': {'role': {}}}
        self.assertFalse(check(target_dict, cred_dict, self.enforcer))

    def test_no_roles_case(self):
        check = _checks.RoleCheck('role', 'spam')

        self.assertFalse(check({}, {}, self.enforcer))


class GenericCheckTestCase(base.PolicyBaseTestCase):
    def test_no_cred(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertFalse(check({'name': 'spam'}, {}, self.enforcer))

    def test_cred_mismatch(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertFalse(
            check({'name': 'spam'}, {'name': 'ham'}, self.enforcer)
        )

    def test_accept(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertTrue(
            check({'name': 'spam'}, {'name': 'spam'}, self.enforcer)
        )

    def test_no_key_match_in_target(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertFalse(
            check({'name1': 'spam'}, {'name': 'spam'}, self.enforcer)
        )

    def test_constant_string_mismatch(self):
        check = _checks.GenericCheck("'spam'", '%(name)s')

        self.assertFalse(check({'name': 'ham'}, {}, self.enforcer))

    def test_constant_string_accept(self):
        check = _checks.GenericCheck("'spam'", '%(name)s')

        self.assertTrue(check({'name': 'spam'}, {}, self.enforcer))

    def test_constant_literal_mismatch(self):
        check = _checks.GenericCheck('True', '%(enabled)s')

        self.assertFalse(check(dict(enabled=False), {}, self.enforcer))

    def test_constant_literal_accept(self):
        check = _checks.GenericCheck('True', '%(enabled)s')

        self.assertTrue(check(dict(enabled=True), {}, self.enforcer))

    def test_deep_credentials_dictionary_lookup(self):
        check = _checks.GenericCheck('a.b.c.d', 'APPLES')

        credentials = {'a': {'b': {'c': {'d': 'APPLES'}}}}

        self.assertTrue(check({}, credentials, self.enforcer))

    def test_missing_credentials_dictionary_lookup(self):
        credentials = {'a': 'APPLES', 'o': {'t': 'ORANGES'}}

        # First a valid check - rest of case is expecting failures
        # Should prove the basic credentials structure before we test
        # for failure cases.
        check = _checks.GenericCheck('o.t', 'ORANGES')
        self.assertTrue(check({}, credentials, self.enforcer))

        # Case where final key is missing
        check = _checks.GenericCheck('o.v', 'ORANGES')
        self.assertFalse(check({}, credentials, self.enforcer))

        # Attempt to access key under a missing dictionary
        check = _checks.GenericCheck('q.v', 'APPLES')
        self.assertFalse(check({}, credentials, self.enforcer))

    def test_single_entry_in_list_accepted(self):
        check = _checks.GenericCheck('a.b.c.d', 'APPLES')
        credentials = {'a': {'b': {'c': {'d': ['APPLES']}}}}
        self.assertTrue(check({}, credentials, self.enforcer))

    def test_multiple_entry_in_list_accepted(self):
        check = _checks.GenericCheck('a.b.c.d', 'APPLES')
        credentials = {
            'a': {'b': {'c': {'d': ['Bananas', 'APPLES', 'Grapes']}}}
        }
        self.assertTrue(check({}, credentials, self.enforcer))

    def test_multiple_entry_in_nested_list_accepted(self):
        check = _checks.GenericCheck('a.b.c.d', 'APPLES')
        credentials = {
            'a': {'b': [{'c': {'d': ['BANANAS', 'APPLES', 'GRAPES']}}, {}]}
        }
        self.assertTrue(check({}, credentials, self.enforcer))

    def test_multiple_entries_one_matches(self):
        check = _checks.GenericCheck(
            'token.catalog.endpoints.id',
            token_fixture.REGION_ONE_PUBLIC_KEYSTONE_ENDPOINT_ID,
        )
        credentials = token_fixture.PROJECT_SCOPED_TOKEN_FIXTURE
        self.assertTrue(check({}, credentials, self.enforcer))

    def test_generic_role_check_matches(self):
        check = _checks.GenericCheck('token.roles.name', 'role1')
        credentials = token_fixture.PROJECT_SCOPED_TOKEN_FIXTURE
        self.assertTrue(check({}, credentials, self.enforcer))

    def test_generic_missing_role_does_not_matches(self):
        check = _checks.GenericCheck('token.roles.name', 'missing')
        credentials = token_fixture.PROJECT_SCOPED_TOKEN_FIXTURE
        self.assertFalse(check({}, credentials, self.enforcer))

    def test_multiple_nested_lists_accepted(self):
        check = _checks.GenericCheck('a.b.c.d', 'APPLES')
        credentials = {
            'a': {
                'b': [
                    {'a': ''},
                    {'c': {'d': ['BANANAS', 'APPLES', 'GRAPES']}},
                    {},
                ]
            }
        }
        self.assertTrue(check({}, credentials, self.enforcer))

    def test_entry_not_in_list_rejected(self):
        check = _checks.GenericCheck('a.b.c.d', 'APPLES')
        credentials = {'a': {'b': {'c': {'d': ['PEACHES', 'PEARS']}}}}
        self.assertFalse(check({}, credentials, self.enforcer))


class FalseCheckTestCase(base.PolicyBaseTestCase):
    def test_str(self):
        check = _checks.FalseCheck()

        self.assertEqual('!', str(check))

    def test_call(self):
        check = _checks.FalseCheck()

        self.assertFalse(check({}, {}, self.enforcer))


class TrueCheckTestCase(base.PolicyBaseTestCase):
    def test_str(self):
        check = _checks.TrueCheck()

        self.assertEqual('@', str(check))

    def test_call(self):
        check = _checks.TrueCheck()

        self.assertTrue(check({}, {}, self.enforcer))


class CheckForTest(_checks.Check):
    def __call__(self, target, creds, enforcer, current_rule=None):
        pass


class CheckTestCase(base.PolicyBaseTestCase):
    def test_init(self):
        check = CheckForTest('kind', 'match')

        self.assertEqual('kind', check.kind)
        self.assertEqual('match', check.match)

    def test_str(self):
        check = CheckForTest('kind', 'match')

        self.assertEqual('kind:match', str(check))


class NotCheckTestCase(base.PolicyBaseTestCase):
    def test_init(self):
        foo = CheckForTest('kind', 'match')
        check = _checks.NotCheck(foo)

        self.assertEqual(foo, check.rule)

    def test_str(self):
        rule = CheckForTest('kind', 'match')
        check = _checks.NotCheck(rule)

        self.assertEqual('not kind:match', str(check))

    def test_call_true(self):
        rule = _checks.TrueCheck()
        check = _checks.NotCheck(rule)
        self.assertFalse(check({}, {}, self.enforcer))

    def test_call_false(self):
        rule = _checks.FalseCheck()
        check = _checks.NotCheck(rule)
        self.assertTrue(check({}, {}, self.enforcer))

    def test_rule_takes_current_rule(self):
        results = []

        class TestCheck(_checks.Check):
            def __call__(self, target, creds, enforcer, current_rule=None):
                results.append((target, creds, enforcer, current_rule))
                return True

        check = _checks.NotCheck(TestCheck('kind', 'match'))

        self.assertFalse(check({}, {}, self.enforcer, current_rule='a_rule'))
        self.assertEqual(
            [({}, {}, self.enforcer, 'a_rule')],
            results,
        )

    def test_rule_does_not_take_current_rule(self):
        results = []

        class TestCheck:
            def __call__(self, target, creds, enforcer):
                results.append((target, creds, enforcer))
                return True

        # this is for the legacy path, and our type hints specifically don't
        # account for this path
        check = _checks.NotCheck(TestCheck())  # type: ignore

        self.assertFalse(check({}, {}, self.enforcer, current_rule='a_rule'))
        self.assertEqual(
            [({}, {}, self.enforcer)],
            results,
        )


class _BoolCheck(_checks.BaseCheck):
    def __init__(self, result):
        self.called = False
        self.result = result

    def __str__(self):
        return str(self.result)

    def __call__(self, target, creds, enforcer, current_rule=None):
        self.called = True
        return self.result


class AndCheckTestCase(base.PolicyBaseTestCase):
    def test_init(self):
        rule1 = CheckForTest('kind1', 'match1')
        rule2 = CheckForTest('kind2', 'match2')
        check = _checks.AndCheck([rule1, rule2])

        self.assertEqual([rule1, rule2], check.rules)

    def test_add_check(self):
        rule1 = CheckForTest('kind1', 'match1')
        rule2 = CheckForTest('kind2', 'match2')
        rule3 = CheckForTest('kind3', 'match3')
        check = _checks.AndCheck([rule1, rule2])
        check.add_check(rule3)

        self.assertEqual([rule1, rule2, rule3], check.rules)

    def test_str(self):
        rule1 = CheckForTest('kind1', 'match1')
        rule2 = CheckForTest('kind2', 'match2')
        check = _checks.AndCheck([rule1, rule2])

        self.assertEqual('(kind1:match1 and kind2:match2)', str(check))

    def test_call_all_false(self):
        rules = [_BoolCheck(False), _BoolCheck(False)]
        check = _checks.AndCheck(rules)

        self.assertFalse(check({}, {}, self.enforcer))
        self.assertTrue(rules[0].called)
        self.assertFalse(rules[1].called)

    def test_call_first_true(self):
        rules = [_BoolCheck(True), _BoolCheck(False)]
        check = _checks.AndCheck(rules)

        self.assertFalse(check({}, {}, self.enforcer))
        self.assertTrue(rules[0].called)
        self.assertTrue(rules[1].called)

    def test_call_second_true(self):
        rules = [_BoolCheck(False), _BoolCheck(True)]
        check = _checks.AndCheck(rules)

        self.assertFalse(check({}, {}, self.enforcer))
        self.assertTrue(rules[0].called)
        self.assertFalse(rules[1].called)

    def test_rule_takes_current_rule(self):
        results = []

        class TestCheck(_checks.Check):
            def __call__(self, target, creds, enforcer, current_rule=None):
                results.append((target, creds, enforcer, current_rule))
                return False

        check = _checks.AndCheck([TestCheck('kind', 'match')])

        self.assertFalse(check({}, {}, self.enforcer, current_rule='a_rule'))
        self.assertEqual(
            [({}, {}, self.enforcer, 'a_rule')],
            results,
        )

    def test_rule_does_not_take_current_rule(self):
        results = []

        class TestCheck:
            def __call__(self, target, creds, enforcer):
                results.append((target, creds, enforcer))
                return False

        # this is for the legacy path, and our type hints specifically don't
        # account for this path
        check = _checks.AndCheck([TestCheck()])  # type: ignore

        self.assertFalse(check({}, {}, self.enforcer, current_rule='a_rule'))
        self.assertEqual(
            [({}, {}, self.enforcer)],
            results,
        )


class OrCheckTestCase(base.PolicyBaseTestCase):
    def test_init(self):
        rule1 = CheckForTest('kind1', 'match1')
        rule2 = CheckForTest('kind2', 'match2')
        check = _checks.OrCheck([rule1, rule2])

        self.assertEqual([rule1, rule2], check.rules)

    def test_add_check(self):
        rule1 = CheckForTest('kind1', 'match1')
        rule2 = CheckForTest('kind2', 'match2')
        rule3 = CheckForTest('kind3', 'match3')
        check = _checks.OrCheck([rule1, rule2])
        check.add_check(rule3)

        self.assertEqual([rule1, rule2, rule3], check.rules)

    def test_pop_check(self):
        rule1 = CheckForTest('kind1', 'match1')
        rule2 = CheckForTest('kind2', 'match2')
        rule3 = CheckForTest('kind3', 'match3')
        check = _checks.OrCheck([rule1, rule2, rule3])
        rules, check1 = check.pop_check()

        self.assertEqual([rule1, rule2], check.rules)
        self.assertEqual(rule3, check1)

    def test_str(self):
        rule1 = CheckForTest('kind1', 'match1')
        rule2 = CheckForTest('kind2', 'match2')
        check = _checks.OrCheck([rule1, rule2])

        self.assertEqual('(kind1:match1 or kind2:match2)', str(check))

    def test_call_all_false(self):
        rules = [_BoolCheck(False), _BoolCheck(False)]
        check = _checks.OrCheck(rules)

        self.assertFalse(check({}, {}, self.enforcer))
        self.assertTrue(rules[0].called)
        self.assertTrue(rules[1].called)

    def test_call_first_true(self):
        rules = [_BoolCheck(True), _BoolCheck(False)]
        check = _checks.OrCheck(rules)

        self.assertTrue(check({}, {}, self.enforcer))
        self.assertTrue(rules[0].called)
        self.assertFalse(rules[1].called)

    def test_call_second_true(self):
        rules = [_BoolCheck(False), _BoolCheck(True)]
        check = _checks.OrCheck(rules)

        self.assertTrue(check({}, {}, self.enforcer))
        self.assertTrue(rules[0].called)
        self.assertTrue(rules[1].called)

    def test_rule_takes_current_rule(self):
        results = []

        class TestCheck(_checks.Check):
            def __call__(self, target, creds, enforcer, current_rule=None):
                results.append((target, creds, enforcer, current_rule))
                return False

        check = _checks.OrCheck([TestCheck('kind', 'match')])

        self.assertFalse(check({}, {}, self.enforcer, current_rule='a_rule'))
        self.assertEqual(
            [({}, {}, self.enforcer, 'a_rule')],
            results,
        )

    def test_rule_does_not_take_current_rule(self):
        results = []

        class TestCheck:
            def __call__(self, target, creds, enforcer):
                results.append((target, creds, enforcer))
                return False

        # this is a test for the legacy path: our type hints explicitly do not
        # handle this
        check = _checks.OrCheck([TestCheck()])  # type: ignore

        self.assertFalse(check({}, {}, self.enforcer, current_rule='a_rule'))
        self.assertEqual(
            [({}, {}, self.enforcer)],
            results,
        )
