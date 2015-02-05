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


import mock
from oslo_serialization import jsonutils
from oslotest import base as test_base
import six
import six.moves.urllib.parse as urlparse
import six.moves.urllib.request as urlrequest

from oslo_policy import _checks
from oslo_policy import policy
from oslo_policy.tests import base


ENFORCER = base.ENFORCER


class CheckRegisterTestCase(test_base.BaseTestCase):
    @mock.patch.object(_checks, 'registered_checks', {})
    def test_register_check(self):
        class TestCheck(_checks.Check):
            pass

        policy.register('spam', TestCheck)

        self.assertEqual(_checks.registered_checks, dict(spam=TestCheck))

    @mock.patch.object(_checks, 'registered_checks', {})
    def test_register_check_decorator(self):
        @policy.register('spam')
        class TestCheck(_checks.Check):
            pass

        self.assertEqual(_checks.registered_checks, dict(spam=TestCheck))


class RuleCheckTestCase(test_base.BaseTestCase):
    @mock.patch.object(ENFORCER, 'rules', {})
    def test_rule_missing(self):
        check = _checks.RuleCheck('rule', 'spam')

        self.assertEqual(check('target', 'creds', ENFORCER), False)

    @mock.patch.object(ENFORCER, 'rules',
                       dict(spam=mock.Mock(return_value=False)))
    def test_rule_false(self):
        enforcer = ENFORCER

        check = _checks.RuleCheck('rule', 'spam')

        self.assertEqual(check('target', 'creds', enforcer), False)
        enforcer.rules['spam'].assert_called_once_with('target', 'creds',
                                                       enforcer)

    @mock.patch.object(ENFORCER, 'rules',
                       dict(spam=mock.Mock(return_value=True)))
    def test_rule_true(self):
        enforcer = ENFORCER
        check = _checks.RuleCheck('rule', 'spam')

        self.assertEqual(check('target', 'creds', enforcer), True)
        enforcer.rules['spam'].assert_called_once_with('target', 'creds',
                                                       enforcer)


class RoleCheckTestCase(base.PolicyBaseTestCase):
    def test_accept(self):
        check = _checks.RoleCheck('role', 'sPaM')

        self.assertEqual(check('target', dict(roles=['SpAm']),
                               self.enforcer), True)

    def test_reject(self):
        check = _checks.RoleCheck('role', 'spam')

        self.assertEqual(check('target', dict(roles=[]), self.enforcer), False)


class HttpCheckTestCase(base.PolicyBaseTestCase):
    def decode_post_data(self, post_data):
        result = {}
        for item in post_data.split('&'):
            key, _sep, value = item.partition('=')
            result[key] = jsonutils.loads(urlparse.unquote_plus(value))

        return result

    @mock.patch.object(urlrequest, 'urlopen',
                       return_value=six.StringIO('True'))
    def test_accept(self, mock_urlopen):
        check = _checks.HttpCheck('http', '//example.com/%(name)s')
        self.assertEqual(check(dict(name='target', spam='spammer'),
                               dict(user='user', roles=['a', 'b', 'c']),
                               self.enforcer),
                         True)
        self.assertEqual(mock_urlopen.call_count, 1)

        args = mock_urlopen.call_args[0]

        self.assertEqual(args[0], 'http://example.com/target')
        self.assertEqual(self.decode_post_data(args[1]), dict(
            target=dict(name='target', spam='spammer'),
            credentials=dict(user='user', roles=['a', 'b', 'c']),
        ))

    @mock.patch.object(urlrequest, 'urlopen',
                       return_value=six.StringIO('other'))
    def test_reject(self, mock_urlopen):
        check = _checks.HttpCheck('http', '//example.com/%(name)s')

        self.assertEqual(check(dict(name='target', spam='spammer'),
                               dict(user='user', roles=['a', 'b', 'c']),
                               self.enforcer),
                         False)
        self.assertEqual(mock_urlopen.call_count, 1)

        args = mock_urlopen.call_args[0]

        self.assertEqual(args[0], 'http://example.com/target')
        self.assertEqual(self.decode_post_data(args[1]), dict(
            target=dict(name='target', spam='spammer'),
            credentials=dict(user='user', roles=['a', 'b', 'c']),
        ))

    @mock.patch.object(urlrequest, 'urlopen',
                       return_value=six.StringIO('True'))
    def test_http_with_objects_in_target(self, mock_urlopen):

        check = _checks.HttpCheck('http', '//example.com/%(name)s')
        target = {'a': object(),
                  'name': 'target',
                  'b': 'test data'}
        self.assertEqual(check(target,
                               dict(user='user', roles=['a', 'b', 'c']),
                               self.enforcer),
                         True)

    @mock.patch.object(urlrequest, 'urlopen',
                       return_value=six.StringIO('True'))
    def test_http_with_strings_in_target(self, mock_urlopen):
        check = _checks.HttpCheck('http', '//example.com/%(name)s')
        target = {'a': 'some_string',
                  'name': 'target',
                  'b': 'test data'}
        self.assertEqual(check(target,
                               dict(user='user', roles=['a', 'b', 'c']),
                               self.enforcer),
                         True)


class GenericCheckTestCase(base.PolicyBaseTestCase):
    def test_no_cred(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertEqual(check(dict(name='spam'), {}, self.enforcer), False)

    def test_cred_mismatch(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertEqual(check(dict(name='spam'),
                               dict(name='ham'),
                               self.enforcer), False)

    def test_accept(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertEqual(check(dict(name='spam'),
                               dict(name='spam'),
                               self.enforcer), True)

    def test_no_key_match_in_target(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertEqual(check(dict(name1='spam'),
                               dict(name='spam'),
                               self.enforcer), False)

    def test_constant_string_mismatch(self):
        check = _checks.GenericCheck("'spam'", '%(name)s')

        self.assertEqual(check(dict(name='ham'),
                               {},
                               self.enforcer), False)

    def test_constant_string_accept(self):
        check = _checks.GenericCheck("'spam'", '%(name)s')

        self.assertEqual(check(dict(name='spam'),
                               {},
                               self.enforcer), True)

    def test_constant_literal_mismatch(self):
        check = _checks.GenericCheck("True", '%(enabled)s')

        self.assertEqual(check(dict(enabled=False),
                               {},
                               self.enforcer), False)

    def test_constant_literal_accept(self):
        check = _checks.GenericCheck("True", '%(enabled)s')

        self.assertEqual(check(dict(enabled=True),
                               {},
                               self.enforcer), True)

    def test_deep_credentials_dictionary_lookup(self):
        check = _checks.GenericCheck("a.b.c.d", 'APPLES')

        credentials = {'a': {'b': {'c': {'d': 'APPLES'}}}}

        self.assertEqual(check({},
                               credentials,
                               self.enforcer), True)

    def test_missing_credentials_dictionary_lookup(self):
        credentials = {'a': 'APPLES', 'o': {'t': 'ORANGES'}}

        # First a valid check - rest of case is expecting failures
        # Should prove the basic credentials structure before we test
        # for failure cases.
        check = _checks.GenericCheck("o.t", 'ORANGES')
        self.assertEqual(check({},
                               credentials,
                               self.enforcer), True)

        # Case where final key is missing
        check = _checks.GenericCheck("o.v", 'ORANGES')
        self.assertEqual(check({},
                               credentials,
                               self.enforcer), False)

        # Attempt to access key under a missing dictionary
        check = _checks.GenericCheck("q.v", 'APPLES')
        self.assertEqual(check({},
                               credentials,
                               self.enforcer), False)


class FalseCheckTestCase(test_base.BaseTestCase):
    def test_str(self):
        check = _checks.FalseCheck()

        self.assertEqual(str(check), '!')

    def test_call(self):
        check = _checks.FalseCheck()

        self.assertEqual(check('target', 'creds', None), False)


class TrueCheckTestCase(test_base.BaseTestCase):
    def test_str(self):
        check = _checks.TrueCheck()

        self.assertEqual(str(check), '@')

    def test_call(self):
        check = _checks.TrueCheck()

        self.assertEqual(check('target', 'creds', None), True)


class CheckForTest(_checks.Check):
    def __call__(self, target, creds, enforcer):
        pass


class CheckTestCase(test_base.BaseTestCase):
    def test_init(self):
        check = CheckForTest('kind', 'match')

        self.assertEqual(check.kind, 'kind')
        self.assertEqual(check.match, 'match')

    def test_str(self):
        check = CheckForTest('kind', 'match')

        self.assertEqual(str(check), 'kind:match')


class NotCheckTestCase(test_base.BaseTestCase):
    def test_init(self):
        check = _checks.NotCheck('rule')

        self.assertEqual(check.rule, 'rule')

    def test_str(self):
        check = _checks.NotCheck('rule')

        self.assertEqual(str(check), 'not rule')

    def test_call_true(self):
        rule = mock.Mock(return_value=True)
        check = _checks.NotCheck(rule)

        self.assertEqual(check('target', 'cred', None), False)
        rule.assert_called_once_with('target', 'cred', None)

    def test_call_false(self):
        rule = mock.Mock(return_value=False)
        check = _checks.NotCheck(rule)

        self.assertEqual(check('target', 'cred', None), True)
        rule.assert_called_once_with('target', 'cred', None)


class AndCheckTestCase(test_base.BaseTestCase):
    def test_init(self):
        check = _checks.AndCheck(['rule1', 'rule2'])

        self.assertEqual(check.rules, ['rule1', 'rule2'])

    def test_add_check(self):
        check = _checks.AndCheck(['rule1', 'rule2'])
        check.add_check('rule3')

        self.assertEqual(check.rules, ['rule1', 'rule2', 'rule3'])

    def test_str(self):
        check = _checks.AndCheck(['rule1', 'rule2'])

        self.assertEqual(str(check), '(rule1 and rule2)')

    def test_call_all_false(self):
        rules = [mock.Mock(return_value=False), mock.Mock(return_value=False)]
        check = _checks.AndCheck(rules)

        self.assertEqual(check('target', 'cred', None), False)
        rules[0].assert_called_once_with('target', 'cred', None)
        self.assertFalse(rules[1].called)

    def test_call_first_true(self):
        rules = [mock.Mock(return_value=True), mock.Mock(return_value=False)]
        check = _checks.AndCheck(rules)

        self.assertFalse(check('target', 'cred', None))
        rules[0].assert_called_once_with('target', 'cred', None)
        rules[1].assert_called_once_with('target', 'cred', None)

    def test_call_second_true(self):
        rules = [mock.Mock(return_value=False), mock.Mock(return_value=True)]
        check = _checks.AndCheck(rules)

        self.assertFalse(check('target', 'cred', None))
        rules[0].assert_called_once_with('target', 'cred', None)
        self.assertFalse(rules[1].called)


class OrCheckTestCase(test_base.BaseTestCase):
    def test_init(self):
        check = _checks.OrCheck(['rule1', 'rule2'])

        self.assertEqual(check.rules, ['rule1', 'rule2'])

    def test_add_check(self):
        check = _checks.OrCheck(['rule1', 'rule2'])
        check.add_check('rule3')

        self.assertEqual(check.rules, ['rule1', 'rule2', 'rule3'])

    def test_str(self):
        check = _checks.OrCheck(['rule1', 'rule2'])

        self.assertEqual(str(check), '(rule1 or rule2)')

    def test_call_all_false(self):
        rules = [mock.Mock(return_value=False), mock.Mock(return_value=False)]
        check = _checks.OrCheck(rules)

        self.assertEqual(check('target', 'cred', None), False)
        rules[0].assert_called_once_with('target', 'cred', None)
        rules[1].assert_called_once_with('target', 'cred', None)

    def test_call_first_true(self):
        rules = [mock.Mock(return_value=True), mock.Mock(return_value=False)]
        check = _checks.OrCheck(rules)

        self.assertEqual(check('target', 'cred', None), True)
        rules[0].assert_called_once_with('target', 'cred', None)
        self.assertFalse(rules[1].called)

    def test_call_second_true(self):
        rules = [mock.Mock(return_value=False), mock.Mock(return_value=True)]
        check = _checks.OrCheck(rules)

        self.assertEqual(check('target', 'cred', None), True)
        rules[0].assert_called_once_with('target', 'cred', None)
        rules[1].assert_called_once_with('target', 'cred', None)
