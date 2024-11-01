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

import copy

from oslo_config import cfg
from oslotest import base as test_base

from oslo_policy import opts


class OptsTestCase(test_base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.conf = cfg.ConfigOpts()
        self.original_opts = opts._options
        opts._options = copy.deepcopy(opts._options)

        def reset():
            opts._options = self.original_opts
        self.addCleanup(reset)

    def test_set_defaults_policy_file(self):
        opts._register(self.conf)
        self.assertNotEqual('new-value.json',
                            self.conf.oslo_policy.policy_file)
        opts.set_defaults(self.conf, policy_file='new-value.json')
        self.assertEqual('new-value.json',
                         self.conf.oslo_policy.policy_file)

    def test_set_defaults_enforce_scope(self):
        opts._register(self.conf)
        self.assertEqual(True,
                         self.conf.oslo_policy.enforce_scope)
        opts.set_defaults(self.conf, enforce_scope=False)
        self.assertEqual(False,
                         self.conf.oslo_policy.enforce_scope)

    def test_set_defaults_two_opts(self):
        opts._register(self.conf)
        self.assertEqual(True,
                         self.conf.oslo_policy.enforce_scope)
        self.assertEqual(True,
                         self.conf.oslo_policy.enforce_new_defaults)
        opts.set_defaults(self.conf, enforce_scope=False,
                          enforce_new_defaults=False)
        self.assertEqual(False,
                         self.conf.oslo_policy.enforce_scope)
        self.assertEqual(False,
                         self.conf.oslo_policy.enforce_new_defaults)
