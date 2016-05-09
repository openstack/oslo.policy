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

LOG = logging.getLogger(__name__)

_generator_opts = [
    cfg.StrOpt('output-file',
               help='Path of the file to write to. Defaults to stdout.'),
    cfg.MultiStrOpt('namespace',
                    required=True,
                    help='Option namespace(s) under "oslo.policy.policies" in '
                         'which to query for options.'),
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


def on_load_failure_callback(*args, **kwargs):
    raise


def generate_sample(args=None):
    logging.basicConfig(level=logging.WARN)
    conf = cfg.ConfigOpts()
    conf.register_cli_opts(_generator_opts)
    conf.register_opts(_generator_opts)
    conf(args)
    _generate_sample(conf.namespace, conf.output_file)
