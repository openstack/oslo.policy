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

import sys

import fixtures
import mock
from oslo_config import cfg
from six import moves
import stevedore
import testtools

from oslo_policy import generator
from oslo_policy import policy
from oslo_policy.tests import base


OPTS = {'base_rules': [policy.RuleDefault('admin', 'is_admin:True',
                                          description='Basic admin check'),
                       policy.RuleDefault('owner',
                                          'project_id:%(project_id)s',
                                          description='This is a long '
                                                      'description to check '
                                                      'that line wrapping '
                                                      'functions properly')],
        'custom_field': [policy.RuleDefault('shared',
                                            'field:networks:shared=True')],
        'rules': [policy.RuleDefault('admin_or_owner',
                                     'rule:admin or rule:owner')],
        }


class GenerateSampleTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super(GenerateSampleTestCase, self).setUp()
        self.enforcer = policy.Enforcer(self.conf, policy_file='policy.yaml')

    def _capture_stdout(self):
        self.useFixture(fixtures.MonkeyPatch('sys.stdout', moves.StringIO()))
        return sys.stdout

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
            generator._generate_sample(['base_rules', 'rules'], output_file)
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
"admin": "is_admin:True"
# This is a long description to check that line wrapping functions
# properly
"owner": "project_id:%(project_id)s"
#
"shared": "field:networks:shared=True"
#
"admin_or_owner": "rule:admin or rule:owner"
'''
        output_file = self.get_config_file_fullname('policy.yaml')
        with mock.patch('stevedore.named.NamedExtensionManager',
                        return_value=test_mgr) as mock_ext_mgr:
            generator._generate_sample(['base_rules', 'rules'], output_file)
            mock_ext_mgr.assert_called_once_with(
                'oslo.policy.policies', names=['base_rules', 'rules'],
                on_load_failure_callback=generator.on_load_failure_callback,
                invoke_on_load=True)

        with open(output_file, 'r') as written_file:
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
"admin": "is_admin:True"
# This is a long description to check that line wrapping functions
# properly
"owner": "project_id:%(project_id)s"
#
"shared": "field:networks:shared=True"
#
"admin_or_owner": "rule:admin or rule:owner"
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


class GeneratorRaiseErrorTestCase(testtools.TestCase):
    def test_generator_raises_error(self):
        """Verifies that errors from extension manager are not suppressed."""
        class FakeException(Exception):
            pass

        class FakeEP(object):

            def __init__(self):
                self.name = 'callback_is_expected'
                self.require = self.resolve
                self.load = self.resolve

            def resolve(self, *args, **kwargs):
                raise FakeException()

        fake_ep = FakeEP()
        fake_eps = mock.Mock(return_value=[fake_ep])
        with mock.patch('pkg_resources.iter_entry_points', fake_eps):
            self.assertRaises(FakeException, generator._generate_sample,
                              fake_ep.name)

    def test_generator_call_with_no_arguments_raises_error(self):
        testargs = ['oslopolicy-sample-generator']
        with mock.patch('sys.argv', testargs):
            self.assertRaises(cfg.RequiredOptError, generator.generate_sample,
                              [])
