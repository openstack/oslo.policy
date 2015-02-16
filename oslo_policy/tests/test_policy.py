# Copyright (c) 2012 OpenStack Foundation.
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

"""Test of Policy Engine"""

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslotest import base as test_base

from oslo_policy import _checks
from oslo_policy import _parser
from oslo_policy.openstack.common import fileutils
from oslo_policy import policy
from oslo_policy.tests import base


class MyException(Exception):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class RulesTestCase(test_base.BaseTestCase):

    def test_init_basic(self):
        rules = policy.Rules()

        self.assertEqual(rules, {})
        self.assertIsNone(rules.default_rule)

    def test_init(self):
        rules = policy.Rules(dict(a=1, b=2, c=3), 'a')

        self.assertEqual(rules, dict(a=1, b=2, c=3))
        self.assertEqual(rules.default_rule, 'a')

    def test_no_default(self):
        rules = policy.Rules(dict(a=1, b=2, c=3))

        self.assertRaises(KeyError, lambda: rules['d'])

    def test_missing_default(self):
        rules = policy.Rules(dict(a=1, c=3), 'b')

        self.assertRaises(KeyError, lambda: rules['d'])

    def test_with_default(self):
        rules = policy.Rules(dict(a=1, b=2, c=3), 'b')

        self.assertEqual(rules['d'], 2)

    def test_retrieval(self):
        rules = policy.Rules(dict(a=1, b=2, c=3), 'b')

        self.assertEqual(rules['a'], 1)
        self.assertEqual(rules['b'], 2)
        self.assertEqual(rules['c'], 3)

    @mock.patch.object(_parser, 'parse_rule', lambda x: x)
    def test_load_json(self):
        exemplar = """{
    "admin_or_owner": [["role:admin"], ["project_id:%(project_id)s"]],
    "default": []
}"""
        rules = policy.Rules.load_json(exemplar, 'default')

        self.assertEqual(rules.default_rule, 'default')
        self.assertEqual(rules, dict(
            admin_or_owner=[['role:admin'], ['project_id:%(project_id)s']],
            default=[],
        ))

    def test_str(self):
        exemplar = """{
    "admin_or_owner": "role:admin or project_id:%(project_id)s"
}"""
        rules = policy.Rules(dict(
            admin_or_owner='role:admin or project_id:%(project_id)s',
        ))

        self.assertEqual(str(rules), exemplar)

    def test_str_true(self):
        exemplar = """{
    "admin_or_owner": ""
}"""
        rules = policy.Rules(dict(
            admin_or_owner=_checks.TrueCheck(),
        ))

        self.assertEqual(str(rules), exemplar)


class EnforcerTest(base.PolicyBaseTestCase):

    def test_load_file(self):
        self.conf.set_override('policy_dirs', [], group='oslo_policy')
        self.enforcer.load_rules(True)
        self.assertIsNotNone(self.enforcer.rules)
        self.assertIn('default', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)

    @mock.patch('oslo_policy.policy.LOG')
    def test_load_directory(self, mock_log):
        self.enforcer.load_rules(True)
        self.assertIsNotNone(self.enforcer.rules)
        loaded_rules = jsonutils.loads(str(self.enforcer.rules))
        self.assertEqual('role:fakeB', loaded_rules['default'])
        self.assertEqual('is_admin:True', loaded_rules['admin'])
        # 3 debug calls showing loading of policy.json,
        # policy.d/a.conf, policy.d/b.conf
        self.assertEqual(mock_log.debug.call_count, 3)

    @mock.patch('oslo_policy.policy.LOG')
    def test_load_multiple_directories(self, mock_log):
        self.conf.set_override('policy_dirs',
                               ['policy.d', 'policy.2.d'],
                               group='oslo_policy')
        self.enforcer.load_rules(True)
        self.assertIsNotNone(self.enforcer.rules)
        loaded_rules = jsonutils.loads(str(self.enforcer.rules))
        self.assertEqual('role:fakeC', loaded_rules['default'])
        self.assertEqual('is_admin:True', loaded_rules['admin'])
        # 4 debug calls showing loading of policy.json,
        # policy.d/a.conf, policy.d/b.conf, policy.2.d/fake.conf
        self.assertEqual(mock_log.debug.call_count, 4)

    @mock.patch('oslo_policy.policy.LOG')
    def test_load_non_existed_directory(self, mock_log):
        self.conf.set_override('policy_dirs',
                               ['policy.d', 'policy.x.d'],
                               group='oslo_policy')
        self.enforcer.load_rules(True)
        self.assertIsNotNone(self.enforcer.rules)
        self.assertIn('default', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)
        # 3 debug calls showing loading of policy.json,
        # policy.d/a.conf, policy.d/b.conf
        self.assertEqual(mock_log.debug.call_count, 3)

    def test_set_rules_type(self):
        self.assertRaises(TypeError,
                          self.enforcer.set_rules,
                          'dummy')

    @mock.patch.object(fileutils, 'delete_cached_file', mock.Mock())
    def test_clear(self):
        # Make sure the rules are reset
        self.enforcer.rules = 'spam'
        filename = self.enforcer.policy_path
        self.enforcer.clear()
        self.assertEqual(self.enforcer.rules, {})
        self.assertEqual(self.enforcer.default_rule, None)
        self.assertEqual(self.enforcer.policy_path, None)
        fileutils.delete_cached_file.assert_called_once_with(filename)

    def test_rule_with_check(self):
        rules_json = """{
                        "deny_stack_user": "not role:stack_user",
                        "cloudwatch:PutMetricData": ""
                        }"""
        rules = policy.Rules.load_json(rules_json)
        self.enforcer.set_rules(rules)
        action = 'cloudwatch:PutMetricData'
        creds = {'roles': ''}
        self.assertEqual(self.enforcer.enforce(action, {}, creds), True)

    def test_enforcer_with_default_rule(self):
        rules_json = """{
                        "deny_stack_user": "not role:stack_user",
                        "cloudwatch:PutMetricData": ""
                        }"""
        rules = policy.Rules.load_json(rules_json)
        default_rule = _checks.TrueCheck()
        enforcer = policy.Enforcer(cfg.CONF, default_rule=default_rule)
        enforcer.set_rules(rules)
        action = 'cloudwatch:PutMetricData'
        creds = {'roles': ''}
        self.assertEqual(enforcer.enforce(action, {}, creds), True)

    def test_enforcer_force_reload_with_overwrite(self):
        # Prepare in memory fake policies.
        self.enforcer.set_rules({'test': _parser.parse_rule('role:test')},
                                use_conf=True)
        self.enforcer.set_rules({'default': _parser.parse_rule('role:fakeZ')},
                                overwrite=False,  # Keeps 'test' role.
                                use_conf=True)

        self.enforcer.overwrite = True

        # Call enforce(), it will load rules from
        # policy configuration files, to overwrite
        # existing fake ones.
        self.assertFalse(self.enforcer.enforce('test', {},
                                               {'roles': ['test']}))
        self.assertTrue(self.enforcer.enforce('default', {},
                                              {'roles': ['fakeB']}))

        # Check against rule dict again from
        # enforcer object directly.
        self.assertNotIn('test', self.enforcer.rules)
        self.assertIn('default', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)
        loaded_rules = jsonutils.loads(str(self.enforcer.rules))
        self.assertEqual(len(loaded_rules), 2)
        self.assertIn('role:fakeB', loaded_rules['default'])
        self.assertIn('is_admin:True', loaded_rules['admin'])

    def test_enforcer_force_reload_without_overwrite(self):
        # Prepare in memory fake policies.
        self.enforcer.set_rules({'test': _parser.parse_rule('role:test')},
                                use_conf=True)
        self.enforcer.set_rules({'default': _parser.parse_rule('role:fakeZ')},
                                overwrite=False,  # Keeps 'test' role.
                                use_conf=True)

        self.enforcer.overwrite = False

        # Call enforce(), it will load rules from
        # policy configuration files, to merge with
        # existing fake ones.
        self.assertTrue(self.enforcer.enforce('test', {},
                                              {'roles': ['test']}))
        # The existing rules have a same key with
        # new loaded ones will be overwrote.
        self.assertFalse(self.enforcer.enforce('default', {},
                                               {'roles': ['fakeZ']}))

        # Check against rule dict again from
        # enforcer object directly.
        self.assertIn('test', self.enforcer.rules)
        self.assertIn('default', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)
        loaded_rules = jsonutils.loads(str(self.enforcer.rules))
        self.assertEqual(len(loaded_rules), 3)
        self.assertIn('role:test', loaded_rules['test'])
        self.assertIn('role:fakeB', loaded_rules['default'])
        self.assertIn('is_admin:True', loaded_rules['admin'])

    def test_enforcer_keep_use_conf_flag_after_reload(self):
        # We initialized enforcer with
        # policy configure files.
        enforcer = policy.Enforcer(cfg.CONF)
        self.assertTrue(enforcer.use_conf)
        self.assertTrue(enforcer.enforce('default', {},
                                         {'roles': ['fakeB']}))
        self.assertFalse(enforcer.enforce('test', {},
                                          {'roles': ['test']}))
        # After enforcement the flag should
        # be remained there.
        self.assertTrue(enforcer.use_conf)
        self.assertFalse(enforcer.enforce('_dynamic_test_rule', {},
                                          {'roles': ['test']}))
        # Then if configure file got changed,
        # reloading will be triggered when calling
        # enforcer(), this case could happen only
        # when use_conf flag equals True.
        rules = jsonutils.loads(str(enforcer.rules))
        with open(enforcer.policy_path, 'r') as f:
            ori_rules = f.read()

        def _remove_dynamic_test_rule():
            with open(enforcer.policy_path, 'w') as f:
                f.write(ori_rules)
        self.addCleanup(_remove_dynamic_test_rule)

        rules['_dynamic_test_rule'] = 'role:test'

        with open(enforcer.policy_path, 'w') as f:
            f.write(jsonutils.dumps(rules))

        self.assertTrue(enforcer.enforce('_dynamic_test_rule', {},
                                         {'roles': ['test']}))

    def test_enforcer_force_reload_false(self):
        self.enforcer.set_rules({'test': 'test'})
        self.enforcer.load_rules(force_reload=False)
        self.assertIn('test', self.enforcer.rules)
        self.assertNotIn('default', self.enforcer.rules)
        self.assertNotIn('admin', self.enforcer.rules)

    def test_enforcer_overwrite_rules(self):
        self.enforcer.set_rules({'test': 'test'})
        self.enforcer.set_rules({'test': 'test1'}, overwrite=True)
        self.assertEqual(self.enforcer.rules, {'test': 'test1'})

    def test_enforcer_update_rules(self):
        self.enforcer.set_rules({'test': 'test'})
        self.enforcer.set_rules({'test1': 'test1'}, overwrite=False)
        self.assertEqual(self.enforcer.rules, {'test': 'test',
                                               'test1': 'test1'})

    def test_enforcer_with_default_policy_file(self):
        enforcer = policy.Enforcer(cfg.CONF)
        self.assertEqual(cfg.CONF.oslo_policy.policy_file,
                         enforcer.policy_file)

    def test_enforcer_with_policy_file(self):
        enforcer = policy.Enforcer(cfg.CONF, policy_file='non-default.json')
        self.assertEqual('non-default.json', enforcer.policy_file)

    def test_get_policy_path_raises_exc(self):
        enforcer = policy.Enforcer(cfg.CONF, policy_file='raise_error.json')
        e = self.assertRaises(cfg.ConfigFilesNotFoundError,
                              enforcer._get_policy_path, enforcer.policy_file)
        self.assertEqual(('raise_error.json', ), e.config_files)

    def test_enforcer_set_rules(self):
        self.enforcer.load_rules()
        self.enforcer.set_rules({'test': 'test1'})
        self.enforcer.load_rules()
        self.assertEqual(self.enforcer.rules, {'test': 'test1'})

    def test_enforcer_default_rule_name(self):
        enforcer = policy.Enforcer(cfg.CONF, default_rule='foo_rule')
        self.assertEqual('foo_rule', enforcer.rules.default_rule)
        self.conf.set_override('policy_default_rule', 'bar_rule',
                               group='oslo_policy')
        enforcer = policy.Enforcer(cfg.CONF, default_rule='foo_rule')
        self.assertEqual('foo_rule', enforcer.rules.default_rule)
        enforcer = policy.Enforcer(cfg.CONF, )
        self.assertEqual('bar_rule', enforcer.rules.default_rule)


class CheckFunctionTestCase(base.PolicyBaseTestCase):

    def test_check_explicit(self):
        rule = base.FakeCheck()
        result = self.enforcer.enforce(rule, 'target', 'creds')
        self.assertEqual(result, ('target', 'creds', self.enforcer))

    def test_check_no_rules(self):
        self.conf.set_override('policy_file', 'empty.json',
                               group='oslo_policy')
        self.enforcer.default_rule = None
        self.enforcer.load_rules()
        result = self.enforcer.enforce('rule', 'target', 'creds')
        self.assertEqual(result, False)

    def test_check_with_rule(self):
        self.enforcer.set_rules(dict(default=base.FakeCheck()))
        result = self.enforcer.enforce('default', 'target', 'creds')

        self.assertEqual(result, ('target', 'creds', self.enforcer))

    def test_check_raises(self):
        self.enforcer.set_rules(dict(default=_checks.FalseCheck()))

        try:
            self.enforcer.enforce('rule', 'target', 'creds',
                                  True, MyException, 'arg1',
                                  'arg2', kw1='kwarg1', kw2='kwarg2')
        except MyException as exc:
            self.assertEqual(exc.args, ('arg1', 'arg2'))
            self.assertEqual(exc.kwargs, dict(kw1='kwarg1', kw2='kwarg2'))
        else:
            self.fail('enforcer.enforce() failed to raise requested exception')
