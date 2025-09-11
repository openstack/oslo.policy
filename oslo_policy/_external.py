#
# Copyright (c) 2015 OpenStack Foundation.
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

import contextlib
import copy
import os
from typing import Any, TYPE_CHECKING

import requests
from requests.exceptions import Timeout

from oslo_policy import _checks
from oslo_policy._i18n import _
from oslo_serialization import jsonutils

if TYPE_CHECKING:
    from oslo_policy.policy import Enforcer


class HttpCheck(_checks.Check):
    """Check ``http:`` rules by calling to a remote server.

    This example implementation simply verifies that the response
    is exactly ``True``.
    """

    def __call__(
        self,
        target: _checks.TargetT,
        creds: _checks.CredsT,
        enforcer: 'Enforcer',
        current_rule: str | None = None,
    ) -> bool:
        timeout = enforcer.conf.oslo_policy.remote_timeout

        url = ('http:' + self.match) % target
        data, json = self._construct_payload(
            creds, current_rule, enforcer, target
        )
        try:
            with contextlib.closing(
                requests.post(url, json=json, data=data, timeout=timeout)
            ) as r:
                return bool(r.text.lstrip('"').rstrip('"') == 'True')
        except Timeout:
            raise RuntimeError('Timeout in REST API call')

    @staticmethod
    def _construct_payload(
        creds: _checks.CredsT,
        current_rule: str | None,
        enforcer: 'Enforcer',
        target: _checks.TargetT,
    ) -> tuple[dict[str, Any], None] | tuple[None, dict[str, Any]]:
        # Convert instances of object() in target temporarily to
        # empty dict to avoid circular reference detection
        # errors in jsonutils.dumps().
        temp_target = copy.deepcopy(target)
        for key in target.keys():
            element = target.get(key)
            if type(element) is object:
                temp_target[key] = {}  # type: ignore
        if (
            enforcer.conf.oslo_policy.remote_content_type
            == 'application/x-www-form-urlencoded'
        ):
            data = {
                'rule': jsonutils.dumps(current_rule),
                'target': jsonutils.dumps(temp_target),
                'credentials': jsonutils.dumps(creds),
            }
            json = None
            return data, json
        else:
            data = None
            json = {
                'rule': current_rule,
                'target': temp_target,
                'credentials': creds,
            }
            return data, json


class HttpsCheck(HttpCheck):
    """Check ``https:`` rules by calling to a remote server.

    This example implementation simply verifies that the response
    is exactly ``True``.
    """

    def __call__(
        self,
        target: _checks.TargetT,
        creds: _checks.CredsT,
        enforcer: 'Enforcer',
        current_rule: str | None = None,
    ) -> bool:
        url = ('https:' + self.match) % target

        cert_file = enforcer.conf.oslo_policy.remote_ssl_client_crt_file
        key_file = enforcer.conf.oslo_policy.remote_ssl_client_key_file
        ca_crt_file = enforcer.conf.oslo_policy.remote_ssl_ca_crt_file
        verify_server = enforcer.conf.oslo_policy.remote_ssl_verify_server_crt
        timeout = enforcer.conf.oslo_policy.remote_timeout

        if cert_file:
            if not os.path.exists(cert_file):
                raise RuntimeError(
                    _('Unable to find ssl cert_file  : %s') % cert_file
                )
            if not os.access(cert_file, os.R_OK):
                raise RuntimeError(
                    _('Unable to access ssl cert_file  : %s') % cert_file
                )
        if key_file:
            if not os.path.exists(key_file):
                raise RuntimeError(
                    _('Unable to find ssl key_file : %s') % key_file
                )
            if not os.access(key_file, os.R_OK):
                raise RuntimeError(
                    _('Unable to access ssl key_file  : %s') % key_file
                )
        cert = (cert_file, key_file)
        if verify_server:
            if ca_crt_file:
                if not os.path.exists(ca_crt_file):
                    raise RuntimeError(
                        _('Unable to find ca cert_file  : %s') % ca_crt_file
                    )
                verify_server = ca_crt_file

        data, json = self._construct_payload(
            creds, current_rule, enforcer, target
        )
        try:
            with contextlib.closing(
                requests.post(
                    url,
                    json=json,
                    data=data,
                    cert=cert,
                    verify=verify_server,
                    timeout=timeout,
                )
            ) as r:
                return bool(r.text.lstrip('"').rstrip('"') == 'True')
        except Timeout:
            raise RuntimeError('Timeout in REST API call')
