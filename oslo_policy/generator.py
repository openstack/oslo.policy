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

import logging
import sys
import textwrap

from oslo_config import cfg
import stevedore

from oslo_policy import policy

LOG = logging.getLogger(__name__)

_generator_opts = [
    cfg.StrOpt('output-file',
               help='Path of the file to write to. Defaults to stdout.'),
]

_rule_opts = [
    cfg.MultiStrOpt('namespace',
                    required=True,
                    help='Option namespace(s) under "oslo.policy.policies" in '
                         'which to query for options.'),
]

_enforcer_opts = [
    cfg.StrOpt('namespace',
               required=True,
               help='Option namespace under "oslo.policy.enforcer" in '
                    'which to look for a policy.Enforcer.'),
]


def _get_policies_dict(namespaces):
    """Find the options available via the given namespaces.

    :param namespaces: a list of namespaces registered under
                       'oslo.policy.policies'
    :returns: a dict of {namespace1: [rule_default_1, rule_default_2],
                         namespace2: [rule_default_3]...}
    """
    mgr = stevedore.named.NamedExtensionManager(
        'oslo.policy.policies',
        names=namespaces,
        on_load_failure_callback=on_load_failure_callback,
        invoke_on_load=True)
    opts = {ep.name: ep.obj for ep in mgr}

    return opts


def _get_enforcer(namespace):
    """Find a policy.Enforcer via an entry point with the given namespace.

    :param namespace: a namespace under oslo.policy.enforcer where the desired
                      enforcer object can be found.
    :returns: a policy.Enforcer object
    """
    mgr = stevedore.named.NamedExtensionManager(
        'oslo.policy.enforcer',
        names=[namespace],
        on_load_failure_callback=on_load_failure_callback,
        invoke_on_load=True)
    enforcer = mgr[namespace].obj

    return enforcer


def _format_help_text(description):
    """Format a comment for a policy based on the description provided.

    :param description: A string with helpful text.
    :returns: A line wrapped comment, or blank comment if description is None
    """
    if not description:
        return '#'

    return textwrap.fill(description, 70, initial_indent='# ',
                         subsequent_indent='# ',
                         break_long_words=False,
                         replace_whitespace=False)


def _format_rule_default_yaml(default, include_help=True):
    """Create a yaml node from the provided policy.RuleDefault.

    :param default: A policy.RuleDefault object
    :returns: A string containing a yaml representation of the RuleDefault
    """
    text = ('"%(name)s": "%(check_str)s"\n' %
            {'name': default.name,
             'check_str': default.check_str})
    if include_help:
        text = ('%(help)s\n%(text)s' %
                {'help': _format_help_text(default.description),
                 'text': text})
    return text


def _sort_and_format_by_section(policies, include_help=True):
    """Generate a list of policy section texts

    The text for a section will be created and returned one at a time. The
    sections are sorted first to provide for consistent output.

    Text is created in yaml format. This is done manually because PyYaml
    does not facilitate outputing comments.

    :param policies: A dict of {section1: [rule_default_1, rule_default_2],
                                section2: [rule_default_3]}
    """
    for section in sorted(policies.keys()):
        rule_defaults = policies[section]
        for rule_default in rule_defaults:
            yield _format_rule_default_yaml(rule_default,
                                            include_help=include_help)


def _generate_sample(namespaces, output_file=None):
    """Generate a sample policy file.

    List all of the policies available via the namespace specified in the
    given configuration and write them to the specified output file.

    :param namespaces: a list of namespaces registered under
                       'oslo.policy.policies'. Stevedore will look here for
                       policy options.
    :param output_file: The path of a file to output to. stdout used if None.
    """
    policies = _get_policies_dict(namespaces)

    output_file = (open(output_file, 'w') if output_file
                   else sys.stdout)

    for section in _sort_and_format_by_section(policies):
        output_file.write(section)


def _generate_policy(namespace, output_file=None):
    """Generate a policy file showing what will be used.

    This takes all registered policies and merges them with what's defined in
    a policy file and outputs the result. That result is the effective policy
    that will be honored by policy checks.

    :param output_file: The path of a file to output to. stdout used if None.
    """
    enforcer = _get_enforcer(namespace)
    # Ensure that files have been parsed
    enforcer.load_rules()

    file_rules = [policy.RuleDefault(name, default.check_str)
                  for name, default in enforcer.file_rules.items()]
    registered_rules = [policy.RuleDefault(name, default.check_str)
                        for name, default in enforcer.registered_rules.items()
                        if name not in enforcer.file_rules]
    policies = {'rules': file_rules + registered_rules}

    output_file = (open(output_file, 'w') if output_file
                   else sys.stdout)

    for section in _sort_and_format_by_section(policies, include_help=False):
        output_file.write(section)


def _list_redundant(namespace):
    """Generate a list of configured policies which match defaults.

    This checks all policies loaded from policy files and checks to see if they
    match registered policies. If so then it is redundant to have them defined
    in a policy file and operators should consider removing them.
    """
    enforcer = _get_enforcer(namespace)
    # Ensure that files have been parsed
    enforcer.load_rules()

    for name, file_rule in enforcer.file_rules.items():
        reg_rule = enforcer.registered_rules.get(name, None)
        if reg_rule:
            if file_rule == reg_rule:
                print(reg_rule)


def on_load_failure_callback(*args, **kwargs):
    raise


def generate_sample(args=None):
    logging.basicConfig(level=logging.WARN)
    conf = cfg.ConfigOpts()
    conf.register_cli_opts(_generator_opts + _rule_opts)
    conf.register_opts(_generator_opts + _rule_opts)
    conf(args)
    _generate_sample(conf.namespace, conf.output_file)


def generate_policy(args=None):
    logging.basicConfig(level=logging.WARN)
    conf = cfg.ConfigOpts()
    conf.register_cli_opts(_generator_opts + _enforcer_opts)
    conf.register_opts(_generator_opts + _enforcer_opts)
    conf(args)
    _generate_policy(conf.namespace, conf.output_file)


def list_redundant(args=None):
    logging.basicConfig(level=logging.WARN)
    conf = cfg.ConfigOpts()
    conf.register_cli_opts(_enforcer_opts)
    conf.register_opts(_enforcer_opts)
    conf(args)
    _list_redundant(conf.namespace)
