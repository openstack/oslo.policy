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
from oslo_policy.tests import base


class CheckRegisterTestCase(test_base.BaseTestCase):
    @mock.patch.object(_checks, 'registered_checks', {})
    def test_register_check(self):
        class TestCheck(_checks.Check):
            pass

        _checks.register('spam', TestCheck)

        self.assertEqual(dict(spam=TestCheck), _checks.registered_checks)

    @mock.patch.object(_checks, 'registered_checks', {})
    def test_register_check_decorator(self):
        @_checks.register('spam')
        class TestCheck(_checks.Check):
            pass

        self.assertEqual(dict(spam=TestCheck), _checks.registered_checks)


class RuleCheckTestCase(base.PolicyBaseTestCase):
    def test_rule_missing(self):
        self.enforcer.rules = {}
        check = _checks.RuleCheck('rule', 'spam')

        self.assertFalse(check('target', 'creds', self.enforcer))

    def test_rule_false(self):
        self.enforcer.rules = dict(spam=mock.Mock(return_value=False))

        check = _checks.RuleCheck('rule', 'spam')

        self.assertFalse(check('target', 'creds', self.enforcer))
        self.enforcer.rules['spam'].assert_called_once_with('target', 'creds',
                                                            self.enforcer)

    def test_rule_true(self):
        self.enforcer.rules = dict(spam=mock.Mock(return_value=True))
        check = _checks.RuleCheck('rule', 'spam')

        self.assertTrue(check('target', 'creds', self.enforcer))
        self.enforcer.rules['spam'].assert_called_once_with('target', 'creds',
                                                            self.enforcer)


class RoleCheckTestCase(base.PolicyBaseTestCase):
    def test_accept(self):
        check = _checks.RoleCheck('role', 'sPaM')

        self.assertTrue(check('target', dict(roles=['SpAm']), self.enforcer))

    def test_reject(self):
        check = _checks.RoleCheck('role', 'spam')

        self.assertFalse(check('target', dict(roles=[]), self.enforcer))


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
        self.assertTrue(check(dict(name='target', spam='spammer'),
                              dict(user='user', roles=['a', 'b', 'c']),
                              self.enforcer))
        self.assertEqual(1, mock_urlopen.call_count)

        args = mock_urlopen.call_args[0]

        self.assertEqual('http://example.com/target', args[0])
        self.assertEqual(dict(
            target=dict(name='target', spam='spammer'),
            credentials=dict(user='user', roles=['a', 'b', 'c']),
        ), self.decode_post_data(args[1]))

    @mock.patch.object(urlrequest, 'urlopen',
                       return_value=six.StringIO('other'))
    def test_reject(self, mock_urlopen):
        check = _checks.HttpCheck('http', '//example.com/%(name)s')

        self.assertFalse(check(dict(name='target', spam='spammer'),
                               dict(user='user', roles=['a', 'b', 'c']),
                               self.enforcer))
        self.assertEqual(1, mock_urlopen.call_count)

        args = mock_urlopen.call_args[0]

        self.assertEqual('http://example.com/target', args[0])
        self.assertEqual(dict(
            target=dict(name='target', spam='spammer'),
            credentials=dict(user='user', roles=['a', 'b', 'c']),
        ), self.decode_post_data(args[1]))

    @mock.patch.object(urlrequest, 'urlopen',
                       return_value=six.StringIO('True'))
    def test_http_with_objects_in_target(self, mock_urlopen):

        check = _checks.HttpCheck('http', '//example.com/%(name)s')
        target = {'a': object(),
                  'name': 'target',
                  'b': 'test data'}
        self.assertTrue(check(target,
                              dict(user='user', roles=['a', 'b', 'c']),
                              self.enforcer))

    @mock.patch.object(urlrequest, 'urlopen',
                       return_value=six.StringIO('True'))
    def test_http_with_strings_in_target(self, mock_urlopen):
        check = _checks.HttpCheck('http', '//example.com/%(name)s')
        target = {'a': 'some_string',
                  'name': 'target',
                  'b': 'test data'}
        self.assertTrue(check(target,
                              dict(user='user', roles=['a', 'b', 'c']),
                              self.enforcer))


class GenericCheckTestCase(base.PolicyBaseTestCase):
    def test_no_cred(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertFalse(check(dict(name='spam'), {}, self.enforcer))

    def test_cred_mismatch(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertFalse(check(dict(name='spam'),
                               dict(name='ham'),
                               self.enforcer))

    def test_accept(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertTrue(check(dict(name='spam'),
                              dict(name='spam'),
                              self.enforcer))

    def test_no_key_match_in_target(self):
        check = _checks.GenericCheck('name', '%(name)s')

        self.assertFalse(check(dict(name1='spam'),
                               dict(name='spam'),
                               self.enforcer))

    def test_constant_string_mismatch(self):
        check = _checks.GenericCheck("'spam'", '%(name)s')

        self.assertFalse(check(dict(name='ham'), {}, self.enforcer))

    def test_constant_string_accept(self):
        check = _checks.GenericCheck("'spam'", '%(name)s')

        self.assertTrue(check(dict(name='spam'), {}, self.enforcer))

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


class FalseCheckTestCase(test_base.BaseTestCase):
    def test_str(self):
        check = _checks.FalseCheck()

        self.assertEqual('!', str(check))

    def test_call(self):
        check = _checks.FalseCheck()

        self.assertFalse(check('target', 'creds', None))


class TrueCheckTestCase(test_base.BaseTestCase):
    def test_str(self):
        check = _checks.TrueCheck()

        self.assertEqual('@', str(check))

    def test_call(self):
        check = _checks.TrueCheck()

        self.assertTrue(check('target', 'creds', None))


class CheckForTest(_checks.Check):
    def __call__(self, target, creds, enforcer):
        pass


class CheckTestCase(test_base.BaseTestCase):
    def test_init(self):
        check = CheckForTest('kind', 'match')

        self.assertEqual('kind', check.kind)
        self.assertEqual('match', check.match)

    def test_str(self):
        check = CheckForTest('kind', 'match')

        self.assertEqual('kind:match', str(check))


class NotCheckTestCase(test_base.BaseTestCase):
    def test_init(self):
        check = _checks.NotCheck('rule')

        self.assertEqual('rule', check.rule)

    def test_str(self):
        check = _checks.NotCheck('rule')

        self.assertEqual('not rule', str(check))

    def test_call_true(self):
        rule = mock.Mock(return_value=True)
        check = _checks.NotCheck(rule)

        self.assertFalse(check('target', 'cred', None))
        rule.assert_called_once_with('target', 'cred', None)

    def test_call_false(self):
        rule = mock.Mock(return_value=False)
        check = _checks.NotCheck(rule)

        self.assertTrue(check('target', 'cred', None))
        rule.assert_called_once_with('target', 'cred', None)


class AndCheckTestCase(test_base.BaseTestCase):
    def test_init(self):
        check = _checks.AndCheck(['rule1', 'rule2'])

        self.assertEqual(['rule1', 'rule2'], check.rules)

    def test_add_check(self):
        check = _checks.AndCheck(['rule1', 'rule2'])
        check.add_check('rule3')

        self.assertEqual(['rule1', 'rule2', 'rule3'], check.rules)

    def test_str(self):
        check = _checks.AndCheck(['rule1', 'rule2'])

        self.assertEqual('(rule1 and rule2)', str(check))

    def test_call_all_false(self):
        rules = [mock.Mock(return_value=False), mock.Mock(return_value=False)]
        check = _checks.AndCheck(rules)

        self.assertFalse(check('target', 'cred', None))
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

        self.assertEqual(['rule1', 'rule2'], check.rules)

    def test_add_check(self):
        check = _checks.OrCheck(['rule1', 'rule2'])
        check.add_check('rule3')

        self.assertEqual(['rule1', 'rule2', 'rule3'], check.rules)

    def test_str(self):
        check = _checks.OrCheck(['rule1', 'rule2'])

        self.assertEqual('(rule1 or rule2)', str(check))

    def test_call_all_false(self):
        rules = [mock.Mock(return_value=False), mock.Mock(return_value=False)]
        check = _checks.OrCheck(rules)

        self.assertFalse(check('target', 'cred', None))
        rules[0].assert_called_once_with('target', 'cred', None)
        rules[1].assert_called_once_with('target', 'cred', None)

    def test_call_first_true(self):
        rules = [mock.Mock(return_value=True), mock.Mock(return_value=False)]
        check = _checks.OrCheck(rules)

        self.assertTrue(check('target', 'cred', None))
        rules[0].assert_called_once_with('target', 'cred', None)
        self.assertFalse(rules[1].called)

    def test_call_second_true(self):
        rules = [mock.Mock(return_value=False), mock.Mock(return_value=True)]
        check = _checks.OrCheck(rules)

        self.assertTrue(check('target', 'cred', None))
        rules[0].assert_called_once_with('target', 'cred', None)
        rules[1].assert_called_once_with('target', 'cred', None)
