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

    @mock.patch('stevedore.named.NamedExtensionManager')
    def test_generate_loadable_yaml(self, mock_named_mgr):
        mock_eps = []
        for name, opts in OPTS.items():
            mock_ep = mock.Mock()
            mock_ep.configure_mock(name=name, obj=opts)
            mock_eps.append(mock_ep)
        mock_named_mgr.return_value = mock_eps

        output_file = self.get_config_file_fullname('policy.yaml')
        generator._generate_sample(['base_rules', 'rules'], output_file)

        self.enforcer.load_rules()

        self.assertIn('owner', self.enforcer.rules)
        self.assertIn('admin', self.enforcer.rules)
        self.assertIn('admin_or_owner', self.enforcer.rules)
        self.assertEqual('project_id:%(project_id)s',
                         str(self.enforcer.rules['owner']))
        self.assertEqual('is_admin:True', str(self.enforcer.rules['admin']))
        self.assertEqual('(rule:admin or rule:owner)',
                         str(self.enforcer.rules['admin_or_owner']))

    @mock.patch('stevedore.named.NamedExtensionManager')
    def test_expected_content(self, mock_named_mgr):
        mock_eps = []
        for name, opts in OPTS.items():
            mock_ep = mock.Mock()
            mock_ep.configure_mock(name=name, obj=opts)
            mock_eps.append(mock_ep)
        mock_named_mgr.return_value = mock_eps

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
        generator._generate_sample(['base_rules', 'rules'], output_file)

        with open(output_file, 'r') as written_file:
            written_policy = written_file.read()

        self.assertEqual(expected, written_policy)

    @mock.patch('stevedore.named.NamedExtensionManager')
    def test_expected_content_stdout(self, mock_named_mgr):
        mock_eps = []
        for name, opts in OPTS.items():
            mock_ep = mock.Mock()
            mock_ep.configure_mock(name=name, obj=opts)
            mock_eps.append(mock_ep)
        mock_named_mgr.return_value = mock_eps

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
        generator._generate_sample(['base_rules', 'rules'], output_file=None)

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
