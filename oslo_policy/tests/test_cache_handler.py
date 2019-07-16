# Copyright (c) 2020 OpenStack Foundation.
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

"""Test the cache handler module"""

import os

import fixtures
from oslotest import base as test_base

from oslo_policy import _cache_handler as _ch


class CacheHandlerTest(test_base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.tmpdir = self.useFixture(fixtures.TempDir())

    def test_read_cached_file(self):
        file_cache = {}

        path = os.path.join(self.tmpdir.path, 'tmpfile')
        with open(path, 'w+') as fp:
            fp.write('test')

        reloaded, data = _ch.read_cached_file(file_cache, path)
        self.assertEqual('test', data)
        self.assertTrue(reloaded)

        reloaded, data = _ch.read_cached_file(file_cache, path)
        self.assertEqual('test', data)
        self.assertFalse(reloaded)

        reloaded, data = _ch.read_cached_file(
            file_cache, path, force_reload=True)
        self.assertEqual('test', data)
        self.assertTrue(reloaded)

    def test_read_cached_file_with_updates(self):
        file_cache = {}

        path = os.path.join(self.tmpdir.path, 'tmpfile')
        with open(path, 'w+') as fp:
            fp.write('test')

        reloaded, data = _ch.read_cached_file(file_cache, path)

        # update the timestamps
        times = (os.stat(path).st_atime + 1, os.stat(path).st_mtime + 1)
        os.utime(path, times)

        reloaded, data = _ch.read_cached_file(file_cache, path)
        self.assertTrue(reloaded)
