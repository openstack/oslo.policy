#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
# #    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import operator
from unittest import mock
import warnings

from oslo_config import cfg
import stevedore
import testtools
import yaml

from oslo_policy import generator
from oslo_policy import policy
from oslo_policy.tests import base
from oslo_serialization import jsonutils


OPTS = {'base_rules': [policy.RuleDefault('admin', 'is_admin:True',
                                          description='Basic admin check'),
                       policy.DocumentedRuleDefault('owner',
                                                    ('project_id:%'
                                                     '(project_id)s'),
                                                    'This is a long '
                                                    'description to check '
                                                    'that line wrapping '
                                                    'functions properly',
                                                    [{'path': '/foo/',
                                                      'method': 'GET'},
                                                     {'path': '/test/',
                                                      'method': 'POST'}])],
        'custom_field': [policy.RuleDefault('shared',
                                            'field:networks:shared=True')],
        'rules': [policy.RuleDefault('admin_or_owner',
                                     'rule:admin or rule:owner')],
        }


class GenerateSampleYAMLTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()
        self.enforcer = policy.Enforcer(self.conf, policy_file='policy.yaml')

    def test_generate_loadable_yaml(self):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        output_file = self.get_config_file_fullname('policy.yaml')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            # generate sample-policy file with only rules
            generator._generate_sample(['base_rules', 'rules'], output_file,
                                       include_help=False)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['base_rules', 'rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        self.enforcer.load_rules()

        self.assertIn('owner', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)
        self.assertIn('admin_or_owner', self.enforcer.rules)
        self.assertEqual('project_id:%(project_id)s',
                         str(self.enforcer.rules['owner']))
        self.assertEqual('is_admin:True', str(self.enforcer.rules['admin']))
        self.assertEqual('(rule:admin or rule:owner)',
                         str(self.enforcer.rules['admin_or_owner']))

    def test_expected_content(self):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        expected = '''# Basic admin check
#"admin": "is_admin:True"

# This is a long description to check that line wrapping functions
# properly
# GET  /foo/
# POST  /test/
#"owner": "project_id:%(project_id)s"

#"shared": "field:networks:shared=True"

#"admin_or_owner": "rule:admin or rule:owner"

'''
        output_file = self.get_config_file_fullname('policy.yaml')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['base_rules', 'rules'], output_file)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['base_rules', 'rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        with open(output_file) as written_file:
            written_policy = written_file.read()

        self.assertEqual(expected, written_policy)

    def test_expected_content_stdout(self):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        expected = '''# Basic admin check
#"admin": "is_admin:True"

# This is a long description to check that line wrapping functions
# properly
# GET  /foo/
# POST  /test/
#"owner": "project_id:%(project_id)s"

#"shared": "field:networks:shared=True"

#"admin_or_owner": "rule:admin or rule:owner"

'''
        stdout = self._capture_stdout()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['base_rules', 'rules'],
                                       output_file=None)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['base_rules', 'rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        self.assertEqual(expected, stdout.getvalue())

    def test_policies_deprecated_for_removal(self):
        rule = policy.RuleDefault(
            name='foo:post_bar',
            check_str='role:fizz',
            description='Create a bar.',
            deprecated_for_removal=True,
            deprecated_reason='This policy is not used anymore',
            deprecated_since='N'
        )
        opts = {'rules': [rule]}

        extensions = []
        for name, opts, in opts.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)

        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['rules']
        )

        expected = '''# DEPRECATED
# "foo:post_bar" has been deprecated since N.
# This policy is not used anymore
# Create a bar.
#"foo:post_bar": "role:fizz"

'''
        stdout = self._capture_stdout()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['rules'], output_file=None)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True
            )
        self.assertEqual(expected, stdout.getvalue())

    def test_deprecated_policies_are_aliased_to_new_names(self):
        deprecated_rule = policy.DeprecatedRule(
            name='foo:post_bar',
            check_str='role:fizz',
            deprecated_reason=(
                'foo:post_bar is being removed in favor of foo:create_bar'
            ),
            deprecated_since='N',
        )
        new_rule = policy.RuleDefault(
            name='foo:create_bar',
            check_str='role:fizz',
            description='Create a bar.',
            deprecated_rule=deprecated_rule,
        )
        opts = {'rules': [new_rule]}

        extensions = []
        for name, opts in opts.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['rules'])

        expected = '''# Create a bar.
#"foo:create_bar": "role:fizz"

# DEPRECATED
# "foo:post_bar":"role:fizz" has been deprecated since N in favor of
# "foo:create_bar":"role:fizz".
# foo:post_bar is being removed in favor of foo:create_bar
# WARNING: A rule name change has been identified.
#          This may be an artifact of new rules being
#          included which require legacy fallback
#          rules to ensure proper policy behavior.
#          Alternatively, this may just be an alias.
#          Please evaluate on a case by case basis
#          keeping in mind the format for aliased
#          rules is:
#          "old_rule_name": "new_rule_name".
# "foo:post_bar": "rule:foo:create_bar"

'''
        stdout = self._capture_stdout()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['rules'], output_file=None)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True
            )
        self.assertEqual(expected, stdout.getvalue())

    def test_deprecated_policies_with_same_name(self):
        deprecated_rule = policy.DeprecatedRule(
            name='foo:create_bar',
            check_str='role:old',
            deprecated_reason=(
                'role:fizz is a more sane default for foo:create_bar'
            ),
            deprecated_since='N',
        )
        new_rule = policy.RuleDefault(
            name='foo:create_bar',
            check_str='role:fizz',
            description='Create a bar.',
            deprecated_rule=deprecated_rule,
        )
        opts = {'rules': [new_rule]}

        extensions = []
        for name, opts in opts.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['rules'])

        expected = '''# Create a bar.
#"foo:create_bar": "role:fizz"

# DEPRECATED
# "foo:create_bar":"role:old" has been deprecated since N in favor of
# "foo:create_bar":"role:fizz".
# role:fizz is a more sane default for foo:create_bar

'''
        stdout = self._capture_stdout()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['rules'], output_file=None)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True
            )
        self.assertEqual(expected, stdout.getvalue())

    def _test_formatting(self, description, expected):
        rule = [policy.RuleDefault('admin', 'is_admin:True',
                                   description=description)]
        ext = stevedore.extension.Extension(name='check_rule',
                                            entry_point=None,
                                            plugin=None, obj=rule)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=[ext], namespace=['check_rule'])

        output_file = self.get_config_file_fullname('policy.yaml')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['check_rule'], output_file)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['check_rule'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        with open(output_file) as written_file:
            written_policy = written_file.read()

        self.assertEqual(expected, written_policy)

    def test_empty_line_formatting(self):
        description = ('Check Summary \n'
                       '\n'
                       'This is a description to '
                       'check that empty line has '
                       'no white spaces.')
        expected = """# Check Summary
#
# This is a description to check that empty line has no white spaces.
#"admin": "is_admin:True"

"""

        self._test_formatting(description, expected)

    def test_paragraph_formatting(self):
        description = """
Here's a neat description with a paragraph. We want to make sure that it wraps
properly.
"""
        expected = """# Here's a neat description with a paragraph. We want \
to make sure
# that it wraps properly.
#"admin": "is_admin:True"

"""

        self._test_formatting(description, expected)

    def test_literal_block_formatting(self):
        description = """Here's another description.

    This one has a literal block.
    These lines should be kept apart.
    They should not be wrapped, even though they may be longer than 70 chars
"""
        expected = """# Here's another description.
#
#     This one has a literal block.
#     These lines should be kept apart.
#     They should not be wrapped, even though they may be longer than 70 chars
#"admin": "is_admin:True"

"""

        self._test_formatting(description, expected)

    def test_invalid_formatting(self):
        description = """Here's a broken description.

We have some text...
    Followed by a literal block without any spaces.
    We don't support definition lists, so this is just wrong!
"""
        expected = """# Here's a broken description.
#
# We have some text...
#
#     Followed by a literal block without any spaces.
#     We don't support definition lists, so this is just wrong!
#"admin": "is_admin:True"

"""

        with warnings.catch_warnings(record=True) as warns:
            self._test_formatting(description, expected)
            self.assertEqual(1, len(warns))
            self.assertTrue(issubclass(warns[-1].category, FutureWarning))
            self.assertIn('Invalid policy description', str(warns[-1].message))


class GenerateSampleJSONTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()
        self.enforcer = policy.Enforcer(self.conf, policy_file='policy.json')

    def test_generate_loadable_json(self):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        output_file = self.get_config_file_fullname('policy.json')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            # generate sample-policy file with only rules
            generator._generate_sample(['base_rules', 'rules'], output_file,
                                       output_format='json',
                                       include_help=False)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['base_rules', 'rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        self.enforcer.load_rules()

        self.assertIn('owner', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)
        self.assertIn('admin_or_owner', self.enforcer.rules)
        self.assertEqual('project_id:%(project_id)s',
                         str(self.enforcer.rules['owner']))
        self.assertEqual('is_admin:True', str(self.enforcer.rules['admin']))
        self.assertEqual('(rule:admin or rule:owner)',
                         str(self.enforcer.rules['admin_or_owner']))

    def test_expected_content(self):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        expected = '''{
    "admin": "is_admin:True",
    "owner": "project_id:%(project_id)s",
    "shared": "field:networks:shared=True",
    "admin_or_owner": "rule:admin or rule:owner"
}
'''
        output_file = self.get_config_file_fullname('policy.json')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['base_rules', 'rules'],
                                       output_file=output_file,
                                       output_format='json')
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['base_rules', 'rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        with open(output_file) as written_file:
            written_policy = written_file.read()

        self.assertEqual(expected, written_policy)

    def test_expected_content_stdout(self):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        expected = '''{
    "admin": "is_admin:True",
    "owner": "project_id:%(project_id)s",
    "shared": "field:networks:shared=True",
    "admin_or_owner": "rule:admin or rule:owner"
}
'''
        stdout = self._capture_stdout()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['base_rules', 'rules'],
                                       output_file=None,
                                       output_format='json')
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['base_rules', 'rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        self.assertEqual(expected, stdout.getvalue())

    @mock.patch.object(generator, 'LOG')
    def test_generate_json_file_log_warning(self, mock_log):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        output_file = self.get_config_file_fullname('policy.json')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            generator._generate_sample(['base_rules', 'rules'], output_file,
                                       output_format='json')
            mock_log.warning.assert_any_call(policy.WARN_JSON)


class GeneratorRaiseErrorTestCase(testtools.TestCase):
    def test_generator_raises_error(self):
        """Verifies that errors from extension manager are not suppressed."""
        class FakeException(Exception):
            pass

        class FakeEP:

            def __init__(self):
                self.name = 'callback_is_expected'
                self.require = self.resolve
                self.load = self.resolve

            def resolve(self, *args, **kwargs):
                raise FakeException()

        fake_ep = FakeEP()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        side_effect=FakeException()):
            self.assertRaises(FakeException, generator._generate_sample,
                              fake_ep.name)

    def test_generator_call_with_no_arguments_raises_error(self):
        testargs = ['oslopolicy-sample-generator']
        with mock.patch('sys.argv', testargs):
            local_conf = cfg.ConfigOpts()
            self.assertRaises(cfg.RequiredOptError, generator.generate_sample,
                              [], local_conf)


class GeneratePolicyTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()

    def test_merged_rules(self):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        # Write the policy file for an enforcer to load
        sample_file = self.get_config_file_fullname('policy-sample.yaml')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            # generate sample-policy file with only rules
            generator._generate_sample(['base_rules', 'rules'], sample_file,
                                       include_help=False)

        enforcer = policy.Enforcer(self.conf, policy_file='policy-sample.yaml')
        # register an opt defined in the file
        enforcer.register_default(policy.RuleDefault('admin',
                                                     'is_admin:False'))
        # register a new opt
        enforcer.register_default(policy.RuleDefault('foo', 'role:foo'))

        # Mock out stevedore to return the configured enforcer
        ext = stevedore.extension.Extension(name='testing', entry_point=None,
                                            plugin=None, obj=enforcer)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=[ext], namespace='testing')

        # Generate a merged file
        merged_file = self.get_config_file_fullname('policy-merged.yaml')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_policy(namespace='testing',
                                       output_file=merged_file)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.enforcer', names=['testing'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        # load the merged file with a new enforcer
        merged_enforcer = policy.Enforcer(self.conf,
                                          policy_file='policy-merged.yaml')
        merged_enforcer.load_rules()
        for rule in ['admin', 'owner', 'admin_or_owner', 'foo']:
            self.assertIn(rule, merged_enforcer.rules)

        self.assertEqual('is_admin:True', str(merged_enforcer.rules['admin']))
        self.assertEqual('role:foo', str(merged_enforcer.rules['foo']))


class ListRedundantTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()

    @mock.patch('warnings.warn')
    def test_matched_rules(self, mock_warn):
        extensions = []
        for name, opts in OPTS.items():
            ext = stevedore.extension.Extension(name=name, entry_point=None,
                                                plugin=None, obj=opts)
            extensions.append(ext)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=extensions, namespace=['base_rules', 'rules'])

        # Write the policy file for an enforcer to load
        sample_file = self.get_config_file_fullname('policy-sample.yaml')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            # generate sample-policy file with only rules
            generator._generate_sample(['base_rules', 'rules'], sample_file,
                                       include_help=False)

        enforcer = policy.Enforcer(self.conf, policy_file='policy-sample.yaml')
        # register opts that match those defined in policy-sample.yaml
        enforcer.register_default(policy.RuleDefault('admin', 'is_admin:True'))
        enforcer.register_default(
            policy.RuleDefault('owner', 'project_id:%(project_id)s'))
        # register a new opt
        deprecated_rule = policy.DeprecatedRule(
            name='old_foo',
            check_str='role:bar',
            deprecated_reason='reason',
            deprecated_since='T'
        )
        enforcer.register_default(
            policy.RuleDefault(
                name='foo',
                check_str='role:foo',
                deprecated_rule=deprecated_rule,
            ),
        )

        # Mock out stevedore to return the configured enforcer
        ext = stevedore.extension.Extension(name='testing', entry_point=None,
                                            plugin=None, obj=enforcer)
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=[ext], namespace='testing')

        stdout = self._capture_stdout()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._list_redundant(namespace='testing')
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.enforcer', names=['testing'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        matches = [line.split(': ', 1) for
                   line in stdout.getvalue().splitlines()]
        matches.sort(key=operator.itemgetter(0))

        # Should be 'admin'
        opt0 = matches[0]
        self.assertEqual('"admin"', opt0[0])
        self.assertEqual('"is_admin:True"', opt0[1])

        # Should be 'owner'
        opt1 = matches[1]
        self.assertEqual('"owner"', opt1[0])
        self.assertEqual('"project_id:%(project_id)s"', opt1[1])

        self.assertFalse(mock_warn.called,
                         'Deprecation warnings not suppressed.')


class UpgradePolicyTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()
        policy_json_contents = jsonutils.dumps({
            "deprecated_name": "rule:admin"
        })
        self.create_config_file('policy.json', policy_json_contents)
        deprecated_policy = policy.DeprecatedRule(
            name='deprecated_name',
            check_str='rule:admin',
            deprecated_reason='test',
            deprecated_since='Stein',
        )
        self.new_policy = policy.DocumentedRuleDefault(
            name='new_policy_name',
            check_str='rule:admin',
            description='test_policy',
            operations=[{'path': '/test', 'method': 'GET'}],
            deprecated_rule=deprecated_policy,
        )
        self.extensions = []
        ext = stevedore.extension.Extension(name='test_upgrade',
                                            entry_point=None,
                                            plugin=None,
                                            obj=[self.new_policy])
        self.extensions.append(ext)
        # Just used for cli opt parsing
        self.local_conf = cfg.ConfigOpts()

    def test_upgrade_policy_json_file(self):
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=self.extensions, namespace='test_upgrade')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            testargs = ['olsopolicy-policy-upgrade',
                        '--policy',
                        self.get_config_file_fullname('policy.json'),
                        '--namespace', 'test_upgrade',
                        '--output-file',
                        self.get_config_file_fullname('new_policy.json'),
                        '--format', 'json']
            with mock.patch('sys.argv', testargs):
                generator.upgrade_policy(conf=self.local_conf)
                new_file = self.get_config_file_fullname('new_policy.json')
                with open(new_file) as fh:
                    new_policy = jsonutils.loads(fh.read())
                self.assertIsNotNone(new_policy.get('new_policy_name'))
                self.assertIsNone(new_policy.get('deprecated_name'))

    @mock.patch.object(generator, 'LOG')
    def test_upgrade_policy_json_file_log_warning(self, mock_log):
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=self.extensions, namespace='test_upgrade')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            testargs = ['olsopolicy-policy-upgrade',
                        '--policy',
                        self.get_config_file_fullname('policy.json'),
                        '--namespace', 'test_upgrade',
                        '--output-file',
                        self.get_config_file_fullname('new_policy.json'),
                        '--format', 'json']
            with mock.patch('sys.argv', testargs):
                generator.upgrade_policy(conf=self.local_conf)
                mock_log.warning.assert_any_call(policy.WARN_JSON)

    def test_upgrade_policy_yaml_file(self):
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=self.extensions, namespace='test_upgrade')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            testargs = ['olsopolicy-policy-upgrade',
                        '--policy',
                        self.get_config_file_fullname('policy.json'),
                        '--namespace', 'test_upgrade',
                        '--output-file',
                        self.get_config_file_fullname('new_policy.yaml'),
                        '--format', 'yaml']
            with mock.patch('sys.argv', testargs):
                generator.upgrade_policy(conf=self.local_conf)
                new_file = self.get_config_file_fullname('new_policy.yaml')
                with open(new_file) as fh:
                    new_policy = yaml.safe_load(fh)
                self.assertIsNotNone(new_policy.get('new_policy_name'))
                self.assertIsNone(new_policy.get('deprecated_name'))

    def test_upgrade_policy_json_stdout(self):
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=self.extensions, namespace='test_upgrade')
        stdout = self._capture_stdout()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            testargs = ['olsopolicy-policy-upgrade',
                        '--policy',
                        self.get_config_file_fullname('policy.json'),
                        '--namespace', 'test_upgrade',
                        '--format', 'json']
            with mock.patch('sys.argv', testargs):
                generator.upgrade_policy(conf=self.local_conf)
                expected = '''{
    "new_policy_name": "rule:admin"
}'''
                self.assertEqual(expected, stdout.getvalue())

    def test_upgrade_policy_yaml_stdout(self):
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=self.extensions, namespace='test_upgrade')
        stdout = self._capture_stdout()
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            testargs = ['olsopolicy-policy-upgrade',
                        '--policy',
                        self.get_config_file_fullname('policy.json'),
                        '--namespace', 'test_upgrade',
                        '--format', 'yaml']
            with mock.patch('sys.argv', testargs):
                generator.upgrade_policy(conf=self.local_conf)
                expected = '''new_policy_name: rule:admin
'''
                self.assertEqual(expected, stdout.getvalue())


@mock.patch('stevedore.named.NamedExtensionManager')
class GetEnforcerTestCase(base.PolicyBaseTestCase):
    def test_get_enforcer(self, mock_manager):
        mock_instance = mock.MagicMock()
        mock_instance.__contains__.return_value = True
        mock_manager.return_value = mock_instance
        mock_item = mock.Mock()
        mock_item.obj = 'test'
        mock_instance.__getitem__.return_value = mock_item
        self.assertEqual('test', generator._get_enforcer('foo'))

    def test_get_enforcer_missing(self, mock_manager):
        mock_instance = mock.MagicMock()
        mock_instance.__contains__.return_value = False
        mock_manager.return_value = mock_instance
        self.assertRaises(KeyError, generator._get_enforcer, 'nonexistent')


class ValidatorTestCase(base.PolicyBaseTestCase):
    def _get_test_enforcer(self):
        test_rules = [policy.RuleDefault('foo', 'foo:bar=baz'),
                      policy.RuleDefault('bar', 'bar:foo=baz')]
        enforcer = policy.Enforcer(self.conf)
        enforcer.register_defaults(test_rules)
        return enforcer

    def _test_policy(self, rule, success=False, missing_file=False):
        policy_file = self.get_config_file_fullname('test.yaml')
        if missing_file:
            policy_file = 'bogus.yaml'
        self.create_config_file('test.yaml', rule)
        self.create_config_file('test.conf',
                                '[oslo_policy]\npolicy_file=%s' % policy_file)
        # Reparse now that we've created our configs
        self.conf(args=['--config-dir', self.config_dir])

        with mock.patch('oslo_policy.generator._get_enforcer') as ge:
            ge.return_value = self._get_test_enforcer()
            result = generator._validate_policy('test')
            if success:
                self.assertEqual(0, result)
            else:
                self.assertEqual(1, result)

    def test_success(self):
        self._test_policy('foo: rule:bar', success=True)

    def test_cyclical_reference(self):
        self._test_policy('foo: rule:bar\nbar: rule:foo')

    def test_invalid_syntax(self):
        self._test_policy('foo: (bar))')

    def test_false_okay(self):
        self._test_policy('foo: !', success=True)

    def test_reference_nonexistent(self):
        self._test_policy('foo: rule:baz')

    def test_nonexistent(self):
        self._test_policy('baz: rule:foo')

    def test_missing_policy_file(self):
        self._test_policy('', missing_file=True)


class ConvertJsonToYamlTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()
        policy_json_contents = jsonutils.dumps({
            "rule1_name": "rule:admin",
            "rule2_name": "rule:overridden",
            "deprecated_rule1_name": "rule:admin"
        })
        self.create_config_file('policy.json', policy_json_contents)
        self.output_file_path = self.get_config_file_fullname(
            'converted_policy.yaml')
        deprecated_policy = policy.DeprecatedRule(
            name='deprecated_rule1_name',
            check_str='rule:admin',
            deprecated_reason='testing',
            deprecated_since='ussuri',
        )
        self.registered_policy = [
            policy.DocumentedRuleDefault(
                name='rule1_name',
                check_str='rule:admin',
                description='test_rule1',
                operations=[{'path': '/test', 'method': 'GET'}],
                deprecated_rule=deprecated_policy,
                scope_types=['system'],
            ),
            policy.RuleDefault(
                name='rule2_name',
                check_str='rule:admin',
            )
        ]
        self.extensions = []
        ext = stevedore.extension.Extension(name='test',
                                            entry_point=None,
                                            plugin=None,
                                            obj=self.registered_policy)
        self.extensions.append(ext)
        # Just used for cli opt parsing
        self.local_conf = cfg.ConfigOpts()

        self.expected = '''# test_rule1
# GET  /test
# Intended scope(s): system
#"rule1_name": "rule:admin"

# rule2_name
"rule2_name": "rule:overridden"

# WARNING: Below rules are either deprecated rules
# or extra rules in policy file, it is strongly
# recommended to switch to new rules.
"deprecated_rule1_name": "rule:admin"
'''

    def _is_yaml(self, data):
        is_yaml = False
        try:
            jsonutils.loads(data)
        except ValueError:
            try:
                yaml.safe_load(data)
                is_yaml = True
            except yaml.scanner.ScannerError:
                pass
        return is_yaml

    def _test_convert_json_to_yaml_file(self, output_to_file=True):
        test_mgr = stevedore.named.NamedExtensionManager.make_test_instance(
            extensions=self.extensions, namespace='test')
        converted_policy_data = None
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr):
            testargs = ['oslopolicy-convert-json-to-yaml',
                        '--namespace', 'test',
                        '--policy-file',
                        self.get_config_file_fullname('policy.json')]
            if output_to_file:
                testargs.extend(['--output-file',
                                 self.output_file_path])
            with mock.patch('sys.argv', testargs):
                generator.convert_policy_json_to_yaml(conf=self.local_conf)
                if output_to_file:
                    with open(self.output_file_path) as fh:
                        converted_policy_data = fh.read()
        return converted_policy_data

    def test_convert_json_to_yaml_file(self):
        converted_policy_data = self._test_convert_json_to_yaml_file()
        self.assertTrue(self._is_yaml(converted_policy_data))
        self.assertEqual(self.expected, converted_policy_data)

    def test_convert_policy_to_stdout(self):
        stdout = self._capture_stdout()
        self._test_convert_json_to_yaml_file(output_to_file=False)
        self.assertEqual(self.expected, stdout.getvalue())

    def test_converted_yaml_is_loadable(self):
        self._test_convert_json_to_yaml_file()
        enforcer = policy.Enforcer(self.conf,
                                   policy_file=self.output_file_path)
        enforcer.load_rules()
        for rule in ['rule2_name', 'deprecated_rule1_name']:
            self.assertIn(rule, enforcer.rules)

    def test_default_rules_comment_out_in_yaml_file(self):
        converted_policy_data = self._test_convert_json_to_yaml_file()
        commented_default_rule = '''# test_rule1
# GET  /test
# Intended scope(s): system
#"rule1_name": "rule:admin"

'''
        self.assertIn(commented_default_rule, converted_policy_data)

    def test_overridden_rules_uncommented_in_yaml_file(self):
        converted_policy_data = self._test_convert_json_to_yaml_file()
        uncommented_overridden_rule = '''# rule2_name
"rule2_name": "rule:overridden"

'''
        self.assertIn(uncommented_overridden_rule, converted_policy_data)

    def test_existing_deprecated_rules_kept_uncommented_in_yaml_file(self):
        converted_policy_data = self._test_convert_json_to_yaml_file()
        existing_deprecated_rule_with_warning = '''# WARNING: Below rules are either deprecated rules
# or extra rules in policy file, it is strongly
# recommended to switch to new rules.
"deprecated_rule1_name": "rule:admin"
'''  # noqa: E501
        self.assertIn(existing_deprecated_rule_with_warning,
                      converted_policy_data)
