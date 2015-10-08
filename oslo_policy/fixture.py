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

__all__ = ['HttpCheckFixture']

import fixtures

from oslo_policy import policy as oslo_policy


class HttpCheckFixture(fixtures.MockPatchObject):
    """Helps short circuit the external http call"""

    def __init__(self, return_value=True):
        """Initialize the fixture.

        :param return_value: True implies the policy check passed and False
               implies that the policy check failed
        :type return_value: boolean
        """
        super(HttpCheckFixture, self).__init__(
            oslo_policy._checks.HttpCheck,
            '__call__',
            return_value=return_value
        )
