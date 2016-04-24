#!/usr/bin/env python

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import sys

from oslo_serialization import jsonutils

from oslo_policy import policy


def _try_rule(key, rule, target, access_data, o):
    try:
        result = rule(target, access_data, o)
        if result:
            print("passed: %s" % key)
        else:
            print("failed: %s" % key)
    except Exception as e:
        print(e)
        print("exception: %s" % rule)


def tool(policy_file, access_file, apply_rule, is_admin=False):
    access = access_file.read()
    access_data = jsonutils.loads(access)['token']
    access_data['roles'] = [role['name'] for role in access_data['roles']]
    access_data['project_id'] = access_data['project']['id']
    access_data['is_admin'] = is_admin
    policy_data = policy_file.read()
    rules = policy.Rules.load(policy_data, "default")

    class Object(object):
        pass
    o = Object()
    o.rules = rules

    target = {"project_id": access_data['project_id']}

    if apply_rule:
        key = apply_rule
        rule = rules[apply_rule]
        _try_rule(key, rule, target, access_data, o)
        return
    for key, rule in rules.items():
        if ":" in key:
            if apply_rule:
                if (apply_rule == key):
                    _try_rule(key, rule, target, access_data, o)
            else:
                _try_rule(key, rule, target, access_data, o)


def main(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(sys.argv[0])
    parser.add_argument(
        '--policy',
        required=True,
        type=argparse.FileType('rb', 0),
        help='path to a policy file')
    parser.add_argument(
        '--access',
        required=True,
        type=argparse.FileType('rb', 0),
        help='path to a file containing OpenStack Identity API' +
        ' access info in JSON format')
    parser.add_argument(
        '--rule',
        help='rule to test')

    parser.add_argument(
        '--is_admin',
        help='set is_admin=True on the credentials used for the evaluation')

    args = parser.parse_args()
    try:
        apply_rule = args.rule
    except Exception:
        apply_rule = None
    try:
        is_admin = args.is_admin.lower() == "true"
    except Exception:
        is_admin = False
    tool(args.policy, args.access, apply_rule, is_admin)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
