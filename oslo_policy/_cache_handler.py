# Copyright 2011 OpenStack Foundation.
# All Rights Reserved.
#
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

import errno
import logging
import os

from oslo_config import cfg

LOG = logging.getLogger(__name__)


def read_cached_file(cache, filename, force_reload=False):
    """Read from a file if it has been modified.

    :param cache: dictionary to hold opaque cache.
    :param filename: the file path to read.
    :param force_reload: Whether to reload the file.
    :returns: A tuple with a boolean specifying if the data is fresh
              or not.
    """

    if force_reload:
        delete_cached_file(cache, filename)

    reloaded = False
    try:
        mtime = os.path.getmtime(filename)
    except OSError as err:
        msg = err.strerror
        LOG.error('Config file not found %(filename)s: %(msg)s',
                  {'filename': filename, 'msg': msg})
        return True, {}

    cache_info = cache.setdefault(filename, {})

    if not cache_info or mtime > cache_info.get('mtime', 0):
        LOG.debug("Reloading cached file %s", filename)
        try:
            with open(filename) as fap:
                cache_info['data'] = fap.read()
        except IOError as err:
            msg = err.strerror
            err_code = err.errno
            LOG.error('IO error loading %(filename)s: %(msg)s',
                      {'filename': filename, 'msg': msg})
            if err_code == errno.EACCES:
                raise cfg.ConfigFilesPermissionDeniedError((filename,))
        except OSError as err:
            msg = err.strerror
            LOG.error('Config file not found %(filename)s: %(msg)s',
                      {'filename': filename, 'msg': msg})
            raise cfg.ConfigFilesNotFoundError((filename,))
        cache_info['mtime'] = mtime
        reloaded = True
    return (reloaded, cache_info['data'])


def delete_cached_file(cache, filename):
    """Delete cached file if present.

    :param cache: dictionary to hold opaque cache.
    :param filename: filename to delete
    """

    try:
        del cache[filename]
    except KeyError:
        pass
