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

import os

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslotest import base as test_base
import six

from oslo_policy import _cache_handler
from oslo_policy import _checks
from oslo_policy import _parser
from oslo_policy import policy
from oslo_policy.tests import base


POLICY_A_CONTENTS = jsonutils.dumps({"default": "role:fakeA"})
POLICY_B_CONTENTS = jsonutils.dumps({"default": "role:fakeB"})
POLICY_FAKE_CONTENTS = jsonutils.dumps({"default": "role:fakeC"})
POLICY_JSON_CONTENTS = jsonutils.dumps({
    "default": "rule:admin",
    "admin": "is_admin:True"
})


class MyException(Exception):
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


class RulesTestCase(test_base.BaseTestCase):

    def test_init_basic(self):
        rules = policy.Rules()

        self.assertEqual({}, rules)
        self.assertIsNone(rules.default_rule)

    def test_init(self):
        rules = policy.Rules(dict(a=1, b=2, c=3), 'a')

        self.assertEqual(dict(a=1, b=2, c=3), rules)
        self.assertEqual('a', rules.default_rule)

    def test_no_default(self):
        rules = policy.Rules(dict(a=1, b=2, c=3))

        self.assertRaises(KeyError, lambda: rules['d'])

    def test_missing_default(self):
        rules = policy.Rules(dict(a=1, c=3), 'b')

        self.assertRaises(KeyError, lambda: rules['d'])

    def test_with_default(self):
        rules = policy.Rules(dict(a=1, b=2, c=3), 'b')

        self.assertEqual(2, rules['d'])

    def test_retrieval(self):
        rules = policy.Rules(dict(a=1, b=2, c=3), 'b')

        self.assertEqual(1, rules['a'])
        self.assertEqual(2, rules['b'])
        self.assertEqual(3, rules['c'])

    @mock.patch.object(_parser, 'parse_rule', lambda x: x)
    def test_load_json(self):
        exemplar = jsonutils.dumps({
            "admin_or_owner": [["role:admin"], ["project_id:%(project_id)s"]],
            "default": []
        })
        rules = policy.Rules.load(exemplar, 'default')

        self.assertEqual('default', rules.default_rule)
        self.assertEqual(dict(
            admin_or_owner=[['role:admin'], ['project_id:%(project_id)s']],
            default=[],
        ), rules)

    @mock.patch.object(_parser, 'parse_rule', lambda x: x)
    def test_load_json_invalid_exc(self):
        # When the JSON isn't valid, ValueError is raised on load_json.
        # Note the trailing , in the exemplar is invalid JSON.
        exemplar = """{
    "admin_or_owner": [["role:admin"], ["project_id:%(project_id)s"]],
    "default": [
}"""
        self.assertRaises(ValueError, policy.Rules.load, exemplar,
                          'default')

    @mock.patch.object(_parser, 'parse_rule', lambda x: x)
    def test_load_yaml(self):
        # Test that simplified YAML can be used with load().
        # Show that YAML allows useful comments.
        exemplar = """
# Define a custom rule.
admin_or_owner: role:admin or project_id:%(project_id)s
# The default rule is used when there's no action defined.
default: []
"""
        rules = policy.Rules.load(exemplar, 'default')

        self.assertEqual('default', rules.default_rule)
        self.assertEqual(dict(
            admin_or_owner='role:admin or project_id:%(project_id)s',
            default=[],
        ), rules)

    @mock.patch.object(_parser, 'parse_rule', lambda x: x)
    def test_load_yaml_invalid_exc(self):
        # When the JSON isn't valid, ValueError is raised on load().
        # Note the trailing , in the exemplar is invalid JSON.
        exemplar = """{
# Define a custom rule.
admin_or_owner: role:admin or project_id:%(project_id)s
# The default rule is used when there's no action defined.
default: [
}"""
        self.assertRaises(ValueError, policy.Rules.load, exemplar,
                          'default')

    @mock.patch.object(_parser, 'parse_rule', lambda x: x)
    def test_from_dict(self):
        expected = {'admin_or_owner': 'role:admin', 'default': '@'}
        rules = policy.Rules.from_dict(expected, 'default')

        self.assertEqual('default', rules.default_rule)
        self.assertEqual(expected, rules)

    def test_str(self):
        exemplar = jsonutils.dumps({
            "admin_or_owner": "role:admin or project_id:%(project_id)s"
        }, indent=4)
        rules = policy.Rules(dict(
            admin_or_owner='role:admin or project_id:%(project_id)s',
        ))

        self.assertEqual(exemplar, str(rules))

    def test_str_true(self):
        exemplar = jsonutils.dumps({
            "admin_or_owner": ""
        }, indent=4)
        rules = policy.Rules(dict(
            admin_or_owner=_checks.TrueCheck(),
        ))

        self.assertEqual(exemplar, str(rules))

    def test_load_json_deprecated(self):
        with self.assertWarnsRegex(DeprecationWarning,
                                   r'load_json\(\).*load\(\)'):
            policy.Rules.load_json(jsonutils.dumps({'default': ''}, 'default'))


class EnforcerTest(base.PolicyBaseTestCase):

    def setUp(self):
        super(EnforcerTest, self).setUp()
        self.create_config_file('policy.json', POLICY_JSON_CONTENTS)

    def check_loaded_files(self, filenames):
        self.assertEqual(
            [self.get_config_file_fullname(n)
             for n in filenames],
            self.enforcer._loaded_files
        )

    def test_load_file(self):
        self.conf.set_override('policy_dirs', [], group='oslo_policy')
        self.enforcer.load_rules(True)
        self.assertIsNotNone(self.enforcer.rules)
        self.assertIn('default', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)

    def test_load_directory(self):
        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)
        self.create_config_file('policy.d/b.conf', POLICY_B_CONTENTS)
        self.enforcer.load_rules(True)
        self.assertIsNotNone(self.enforcer.rules)
        loaded_rules = jsonutils.loads(str(self.enforcer.rules))
        self.assertEqual('role:fakeB', loaded_rules['default'])
        self.assertEqual('is_admin:True', loaded_rules['admin'])
        self.check_loaded_files([
            'policy.json',
            'policy.d/a.conf',
            'policy.d/b.conf',
        ])

    def test_load_directory_caching_with_files_updated(self):
        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)

        self.enforcer.load_rules(False)
        self.assertIsNotNone(self.enforcer.rules)

        old = six.next(six.itervalues(
            self.enforcer._policy_dir_mtimes))
        self.assertEqual(1, len(self.enforcer._policy_dir_mtimes))

        # Touch the file
        conf_path = os.path.join(self.config_dir, 'policy.d/a.conf')
        stinfo = os.stat(conf_path)
        os.utime(conf_path, (stinfo.st_atime + 10, stinfo.st_mtime + 10))

        self.enforcer.load_rules(False)
        self.assertEqual(1, len(self.enforcer._policy_dir_mtimes))
        self.assertEqual(old, six.next(six.itervalues(
            self.enforcer._policy_dir_mtimes)))

        loaded_rules = jsonutils.loads(str(self.enforcer.rules))
        self.assertEqual('is_admin:True', loaded_rules['admin'])
        self.check_loaded_files([
            'policy.json',
            'policy.d/a.conf',
            'policy.d/a.conf',
        ])

    def test_load_directory_caching_with_files_same(self, overwrite=True):
        self.enforcer = policy.Enforcer(self.conf, overwrite=overwrite)

        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)

        self.enforcer.load_rules(False)
        self.assertIsNotNone(self.enforcer.rules)

        old = six.next(six.itervalues(
            self.enforcer._policy_dir_mtimes))
        self.assertEqual(1, len(self.enforcer._policy_dir_mtimes))

        self.enforcer.load_rules(False)
        self.assertEqual(1, len(self.enforcer._policy_dir_mtimes))
        self.assertEqual(old, six.next(six.itervalues(
            self.enforcer._policy_dir_mtimes)))

        loaded_rules = jsonutils.loads(str(self.enforcer.rules))
        self.assertEqual('is_admin:True', loaded_rules['admin'])
        self.check_loaded_files([
            'policy.json',
            'policy.d/a.conf',
        ])

    def test_load_directory_caching_with_files_same_but_overwrite_false(self):
        self.test_load_directory_caching_with_files_same(overwrite=False)

    def test_load_multiple_directories(self):
        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)
        self.create_config_file('policy.d/b.conf', POLICY_B_CONTENTS)
        self.create_config_file('policy.2.d/fake.conf', POLICY_FAKE_CONTENTS)
        self.conf.set_override('policy_dirs',
                               ['policy.d', 'policy.2.d'],
                               group='oslo_policy')
        self.enforcer.load_rules(True)
        self.assertIsNotNone(self.enforcer.rules)
        loaded_rules = jsonutils.loads(str(self.enforcer.rules))
        self.assertEqual('role:fakeC', loaded_rules['default'])
        self.assertEqual('is_admin:True', loaded_rules['admin'])
        self.check_loaded_files([
            'policy.json',
            'policy.d/a.conf',
            'policy.d/b.conf',
            'policy.2.d/fake.conf',
        ])

    def test_load_non_existed_directory(self):
        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)
        self.conf.set_override('policy_dirs',
                               ['policy.d', 'policy.x.d'],
                               group='oslo_policy')
        self.enforcer.load_rules(True)
        self.assertIsNotNone(self.enforcer.rules)
        self.assertIn('default', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)
        self.check_loaded_files(['policy.json', 'policy.d/a.conf'])

    def test_load_policy_dirs_with_non_directory(self):
        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)
        self.conf.set_override('policy_dirs',
                               ['policy.d/a.conf'],
                               group='oslo_policy')
        self.assertRaises(ValueError, self.enforcer.load_rules, True)

    def test_set_rules_type(self):
        self.assertRaises(TypeError,
                          self.enforcer.set_rules,
                          'dummy')

    @mock.patch.object(_cache_handler, 'delete_cached_file', mock.Mock())
    def test_clear(self):
        # Make sure the rules are reset
        self.enforcer.rules = 'spam'
        self.enforcer.clear()
        self.assertEqual({}, self.enforcer.rules)
        self.assertIsNone(self.enforcer.default_rule)
        self.assertIsNone(self.enforcer.policy_path)

    def test_rule_with_check(self):
        rules_json = jsonutils.dumps({
            "deny_stack_user": "not role:stack_user",
            "cloudwatch:PutMetricData": ""
        })
        rules = policy.Rules.load(rules_json)
        self.enforcer.set_rules(rules)
        action = 'cloudwatch:PutMetricData'
        creds = {'roles': ''}
        self.assertTrue(self.enforcer.enforce(action, {}, creds))

    def test_enforcer_with_default_rule(self):
        rules_json = jsonutils.dumps({
            "deny_stack_user": "not role:stack_user",
            "cloudwatch:PutMetricData": ""
        })
        rules = policy.Rules.load(rules_json)
        default_rule = _checks.TrueCheck()
        enforcer = policy.Enforcer(self.conf, default_rule=default_rule)
        enforcer.set_rules(rules)
        action = 'cloudwatch:PutMetricData'
        creds = {'roles': ''}
        self.assertTrue(enforcer.enforce(action, {}, creds))

    def test_enforcer_force_reload_with_overwrite(self):
        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)
        self.create_config_file('policy.d/b.conf', POLICY_B_CONTENTS)

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
        self.assertEqual(2, len(loaded_rules))
        self.assertIn('role:fakeB', loaded_rules['default'])
        self.assertIn('is_admin:True', loaded_rules['admin'])

    def test_enforcer_force_reload_without_overwrite(self):
        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)
        self.create_config_file('policy.d/b.conf', POLICY_B_CONTENTS)

        # Prepare in memory fake policies.
        self.enforcer.set_rules({'test': _parser.parse_rule('role:test')},
                                use_conf=True)
        self.enforcer.set_rules({'default': _parser.parse_rule('role:fakeZ')},
                                overwrite=False,  # Keeps 'test' role.
                                use_conf=True)

        self.enforcer.overwrite = False
        self.enforcer._is_directory_updated = lambda x, y: True

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
        self.assertEqual(3, len(loaded_rules))
        self.assertIn('role:test', loaded_rules['test'])
        self.assertIn('role:fakeB', loaded_rules['default'])
        self.assertIn('is_admin:True', loaded_rules['admin'])

    def test_enforcer_keep_use_conf_flag_after_reload(self):
        self.create_config_file('policy.d/a.conf', POLICY_A_CONTENTS)
        self.create_config_file('policy.d/b.conf', POLICY_B_CONTENTS)

        # We initialized enforcer with
        # policy configure files.
        enforcer = policy.Enforcer(self.conf)
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
        rules['_dynamic_test_rule'] = 'role:test'

        with open(enforcer.policy_path, 'w') as f:
            f.write(jsonutils.dumps(rules))

        enforcer.load_rules(force_reload=True)
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
        self.assertEqual({'test': 'test1'}, self.enforcer.rules)

    def test_enforcer_update_rules(self):
        self.enforcer.set_rules({'test': 'test'})
        self.enforcer.set_rules({'test1': 'test1'}, overwrite=False)
        self.assertEqual({'test': 'test', 'test1': 'test1'},
                         self.enforcer.rules)

    def test_enforcer_with_default_policy_file(self):
        enforcer = policy.Enforcer(self.conf)
        self.assertEqual(self.conf.oslo_policy.policy_file,
                         enforcer.policy_file)

    def test_enforcer_with_policy_file(self):
        enforcer = policy.Enforcer(self.conf, policy_file='non-default.json')
        self.assertEqual('non-default.json', enforcer.policy_file)

    def test_get_policy_path_raises_exc(self):
        enforcer = policy.Enforcer(self.conf, policy_file='raise_error.json')
        e = self.assertRaises(cfg.ConfigFilesNotFoundError,
                              enforcer._get_policy_path, enforcer.policy_file)
        self.assertEqual(('raise_error.json', ), e.config_files)

    def test_enforcer_set_rules(self):
        self.enforcer.load_rules()
        self.enforcer.set_rules({'test': 'test1'})
        self.enforcer.load_rules()
        self.assertEqual({'test': 'test1'}, self.enforcer.rules)

    def test_enforcer_default_rule_name(self):
        enforcer = policy.Enforcer(self.conf, default_rule='foo_rule')
        self.assertEqual('foo_rule', enforcer.rules.default_rule)
        self.conf.set_override('policy_default_rule', 'bar_rule',
                               group='oslo_policy')
        enforcer = policy.Enforcer(self.conf, default_rule='foo_rule')
        self.assertEqual('foo_rule', enforcer.rules.default_rule)
        enforcer = policy.Enforcer(self.conf, )
        self.assertEqual('bar_rule', enforcer.rules.default_rule)


class CheckFunctionTestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(CheckFunctionTestCase, self).setUp()
        self.create_config_file('policy.json', POLICY_JSON_CONTENTS)

    def test_check_explicit(self):
        rule = base.FakeCheck()
        result = self.enforcer.enforce(rule, 'target', 'creds')
        self.assertEqual(('target', 'creds', self.enforcer), result)

    def test_check_no_rules(self):
        # Clear the policy.json file created in setUp()
        self.create_config_file('policy.json', "{}")
        self.enforcer.default_rule = None
        self.enforcer.load_rules()
        result = self.enforcer.enforce('rule', 'target', 'creds')
        self.assertFalse(result)

    def test_check_with_rule(self):
        self.enforcer.set_rules(dict(default=base.FakeCheck()))
        result = self.enforcer.enforce('default', 'target', 'creds')

        self.assertEqual(('target', 'creds', self.enforcer), result)

    def test_check_rule_not_exist_not_empty_policy_file(self):
        # If the rule doesn't exist, then enforce() fails rather than KeyError.

        # This test needs a non-empty file otherwise the code short-circuits.
        self.create_config_file('policy.json', jsonutils.dumps({"a_rule": []}))
        self.enforcer.default_rule = None
        self.enforcer.load_rules()
        result = self.enforcer.enforce('rule', 'target', 'creds')
        self.assertFalse(result)

    def test_check_raise_default(self):
        # When do_raise=True and exc is not used then PolicyNotAuthorized is
        # raised.
        self.enforcer.set_rules(dict(default=_checks.FalseCheck()))

        self.assertRaises(policy.PolicyNotAuthorized, self.enforcer.enforce,
                          'rule', 'target', 'creds', True)

    def test_check_raise_custom_exception(self):
        self.enforcer.set_rules(dict(default=_checks.FalseCheck()))

        exc = self.assertRaises(
            MyException, self.enforcer.enforce, 'rule', 'target', 'creds',
            True, MyException, 'arg1', 'arg2', kw1='kwarg1', kw2='kwarg2')
        self.assertEqual(('arg1', 'arg2'), exc.args)
        self.assertEqual(dict(kw1='kwarg1', kw2='kwarg2'), exc.kwargs)


class RegisterCheckTestCase(base.PolicyBaseTestCase):

    @mock.patch.object(_checks, 'registered_checks', {})
    def test_register_check(self):
        class TestCheck(policy.Check):
            pass

        policy.register('spam', TestCheck)

        self.assertEqual(dict(spam=TestCheck), _checks.registered_checks)


class BaseCheckTypesTestCase(base.PolicyBaseTestCase):

    @mock.patch.object(_checks, 'registered_checks', {})
    def test_base_check_types_are_public(self):
        '''Check that those check types are part of public API.

           They are blessed to be used by library consumers.
        '''
        for check_type in (policy.AndCheck, policy.NotCheck,
                           policy.OrCheck, policy.RuleCheck):
            class TestCheck(check_type):
                pass

            check_str = str(check_type)
            policy.register(check_str, TestCheck)
            self.assertEqual(
                TestCheck, _checks.registered_checks[check_str],
                message='%s check type is not public.' % check_str)
