# Copyright (c) 2018 OpenStack Foundation.
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

from oslo_serialization import jsonutils

from oslo_policy import shell
from oslo_policy.tests import base
from oslo_policy.tests import token_fixture


class CheckerTestCase(base.PolicyBaseTestCase):

    SAMPLE_POLICY = '''---
"sample_rule": "role:service"
"sampleservice:sample_rule": ""
'''

    def setUp(self):
        super(CheckerTestCase, self).setUp()
        self.create_config_file("policy.yaml", self.SAMPLE_POLICY)
        self.create_config_file(
            "access.json",
            jsonutils.dumps(token_fixture.SCOPED_TOKEN_FIXTURE))

    def test_all_nonadmin(self):

        policy_file = open(self.get_config_file_fullname('policy.yaml'), 'r')
        access_file = open(self.get_config_file_fullname('access.json'), 'r')
        apply_rule = None
        is_admin = False
        stdout = self._capture_stdout()

        shell.tool(policy_file, access_file, apply_rule, is_admin)

        expected = '''passed: sampleservice:sample_rule
'''
        self.assertEqual(expected, stdout.getvalue())
