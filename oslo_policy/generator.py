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
import warnings
import yaml

from oslo_config import cfg
from oslo_serialization import jsonutils
import stevedore

from oslo_policy import policy

LOG = logging.getLogger(__name__)

GENERATOR_OPTS = [
    cfg.StrOpt('output-file',
               help='Path of the file to write to. Defaults to stdout.'),
    cfg.BoolOpt('exclude-deprecated',
                default=False,
                help='If True, exclude deprecated entries from the generated '
                     'output.'),
]

RULE_OPTS = [
    cfg.MultiStrOpt('namespace',
                    help='Option namespace(s) under "oslo.policy.policies" in '
                         'which to query for options.'),
    cfg.StrOpt('format',
               deprecated_for_removal=True,
               deprecated_since='Victoria',
               deprecated_reason="""
``policy_file`` support for JSON formatted file is deprecated.
So these tools also deprecate the support of generating or
upgrading policy file in JSON format.
""",
               help='Desired format for the output.',
               default='yaml',
               choices=['json', 'yaml']),
]

ENFORCER_OPTS = [
    cfg.StrOpt('namespace',
               help='Option namespace under "oslo.policy.enforcer" in '
                    'which to look for a policy.Enforcer.'),
]

UPGRADE_OPTS = [
    cfg.StrOpt('policy',
               required=True,
               help='Path to the policy file which need to be updated.')
]

CONVERT_OPTS = [
    cfg.MultiStrOpt('namespace',
                    required=True,
                    help='Option namespace(s) under "oslo.policy.policies" in '
                         'which to query for options.'),
    cfg.StrOpt('policy-file',
               required=True,
               help='Path to the policy file which need to be converted to '
                    'yaml format.')
]


def get_policies_dict(namespaces):
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
    if namespace not in mgr:
        raise KeyError('Namespace "%s" not found.' % namespace)
    enforcer = mgr[namespace].obj

    return enforcer


def _format_help_text(description):
    """Format a comment for a policy based on the description provided.

    :param description: A string with helpful text.
    :returns: A line wrapped comment, or blank comment if description is None
    """
    if not description:
        return '#'

    formatted_lines = []
    paragraph = []

    def _wrap_paragraph(lines):
        return textwrap.wrap(' '.join(lines), 70, initial_indent='# ',
                             subsequent_indent='# ')

    for line in description.strip().splitlines():
        if not line.strip():
            # empty line -> line break, so dump anything we have
            formatted_lines.extend(_wrap_paragraph(paragraph))
            formatted_lines.append('#')
            paragraph = []
        elif len(line) == len(line.lstrip()):
            # no leading whitespace = paragraph, which should be wrapped
            paragraph.append(line.rstrip())
        else:
            # leading whitespace - literal block, which should not be wrapping
            if paragraph:
                # ...however, literal blocks need a new line before them to
                # delineate things
                # TODO(stephenfin): Raise an exception here and stop doing
                # anything else in oslo.policy 2.0
                warnings.warn(
                    'Invalid policy description: literal blocks must be '
                    'preceded by a new line. This will raise an exception in '
                    'a future version of oslo.policy:\n%s' % description,
                    FutureWarning)
                formatted_lines.extend(_wrap_paragraph(paragraph))
                formatted_lines.append('#')
                paragraph = []

            formatted_lines.append('# %s' % line.rstrip())

    if paragraph:
        # dump anything we might still have in the buffer
        formatted_lines.extend(_wrap_paragraph(paragraph))

    return '\n'.join(formatted_lines)


def _format_rule_default_yaml(default, include_help=True, comment_rule=True,
                              add_deprecated_rules=True):
    """Create a yaml node from policy.RuleDefault or policy.DocumentedRuleDefault.

    :param default: A policy.RuleDefault or policy.DocumentedRuleDefault object
    :param comment_rule: By default rules will be commented out in generated
                         yaml format text. If you want to keep few or all rules
                         uncommented then pass this arg as False.
    :param add_deprecated_rules: Whether to add the deprecated rules in format
                                 text.
    :returns: A string containing a yaml representation of the RuleDefault
    """  # noqa: E501
    text = ('"%(name)s": "%(check_str)s"\n' %
            {'name': default.name,
             'check_str': default.check_str})

    if include_help:
        op = ""
        if hasattr(default, 'operations'):
            for operation in default.operations:
                if operation['method'] and operation['path']:
                    op += ('# %(method)s  %(path)s\n' %
                           {'method': operation['method'],
                            'path': operation['path']})
        intended_scope = ""
        if getattr(default, 'scope_types', None) is not None:
            intended_scope = (
                '# Intended scope(s): ' + ', '.join(default.scope_types) + '\n'
            )
        comment = '#' if comment_rule else ''
        text = ('%(op)s%(scope)s%(comment)s%(text)s\n' %
                {'op': op,
                 'scope': intended_scope,
                 'comment': comment,
                 'text': text})
        if default.description:
            text = _format_help_text(default.description) + '\n' + text

    if add_deprecated_rules and default.deprecated_for_removal:
        text = (
            '# DEPRECATED\n# "%(name)s" has been deprecated since '
            '%(since)s.\n%(reason)s\n%(text)s'
        ) % {'name': default.name,
             'since': default.deprecated_since,
             'reason': _format_help_text(default.deprecated_reason),
             'text': text}
    elif add_deprecated_rules and default.deprecated_rule:
        deprecated_reason = (
            default.deprecated_rule.deprecated_reason or
            default.deprecated_reason
        )
        deprecated_since = (
            default.deprecated_rule.deprecated_since or
            default.deprecated_since
        )

        # This issues a deprecation warning but aliases the old policy name
        # with the new policy name for compatibility.
        deprecated_text = (
            '"%(old_name)s":"%(old_check_str)s" has been deprecated '
            'since %(since)s in favor of "%(name)s":"%(check_str)s".'
        ) % {
            'old_name': default.deprecated_rule.name,
            'old_check_str': default.deprecated_rule.check_str,
            'since': deprecated_since,
            'name': default.name,
            'check_str': default.check_str,
        }
        text = '{text}# DEPRECATED\n{deprecated_text}\n{reason}\n'.format(
            text=text,
            reason=_format_help_text(deprecated_reason),
            deprecated_text=_format_help_text(deprecated_text)
        )

        if default.name != default.deprecated_rule.name:
            text += ('# WARNING: A rule name change has been identified.\n'
                     '#          This may be an artifact of new rules being\n'
                     '#          included which require legacy fallback\n'
                     '#          rules to ensure proper policy behavior.\n'
                     '#          Alternatively, this may just be an alias.\n'
                     '#          Please evaluate on a case by case basis\n'
                     '#          keeping in mind the format for aliased\n'
                     '#          rules is:\n'
                     '#          "old_rule_name": "new_rule_name".\n')
            text += ('# "%(old_name)s": "rule:%(name)s"\n' %
                     {'old_name': default.deprecated_rule.name,
                      'name': default.name})
        text += '\n'

    return text


def _format_rule_default_json(default):
    """Create a json node from policy.RuleDefault or policy.DocumentedRuleDefault.

    :param default: A policy.RuleDefault or policy.DocumentedRuleDefault object
    :returns: A string containing a json representation of the RuleDefault
    """  # noqa: E501
    return ('"%(name)s": "%(check_str)s"' %
            {'name': default.name,
             'check_str': default.check_str})


def _sort_and_format_by_section(policies, output_format='yaml',
                                include_help=True, exclude_deprecated=False):
    """Generate a list of policy section texts

    The text for a section will be created and returned one at a time. The
    sections are sorted first to provide for consistent output.

    Text is created in yaml format. This is done manually because PyYaml
    does not facilitate outputing comments.

    :param policies: A dict of {section1: [rule_default_1, rule_default_2],
                                section2: [rule_default_3]}
    :param output_format: The format of the file to output to.
    :param exclude_deprecated: If to exclude deprecated policy rule entries,
                               defaults to False.
    """
    for section in sorted(policies.keys()):
        rule_defaults = policies[section]
        for rule_default in rule_defaults:
            if output_format == 'yaml':
                yield _format_rule_default_yaml(
                    rule_default,
                    include_help=include_help,
                    add_deprecated_rules=not exclude_deprecated)
            elif output_format == 'json':
                LOG.warning(policy.WARN_JSON)
                yield _format_rule_default_json(rule_default)


def _generate_sample(namespaces, output_file=None, output_format='yaml',
                     include_help=True, exclude_deprecated=False):
    """Generate a sample policy file.

    List all of the policies available via the namespace specified in the
    given configuration and write them to the specified output file.

    :param namespaces: a list of namespaces registered under
                       'oslo.policy.policies'. Stevedore will look here for
                       policy options.
    :param output_file: The path of a file to output to. stdout used if None.
    :param output_format: The format of the file to output to.
    :param include_help: True, generates a sample-policy file with help text
                         along with rules in which everything is commented out.
                         False, generates a sample-policy file with only rules.
    :param exclude_deprecated: If to exclude deprecated policy rule entries,
                               defaults to False.
    """
    policies = get_policies_dict(namespaces)

    output_file = (open(output_file, 'w') if output_file
                   else sys.stdout)

    sections_text = []
    for section in _sort_and_format_by_section(
            policies, output_format,
            include_help=include_help,
            exclude_deprecated=exclude_deprecated):
        sections_text.append(section)

    if output_format == 'yaml':
        output_file.writelines(sections_text)
    elif output_format == 'json':
        LOG.warning(policy.WARN_JSON)
        output_file.writelines((
            '{\n    ',
            ',\n    '.join(sections_text),
            '\n}\n'))

    if output_file != sys.stdout:
        output_file.close()


def _generate_policy(namespace, output_file=None, exclude_deprecated=False):
    """Generate a policy file showing what will be used.

    This takes all registered policies and merges them with what's defined in
    a policy file and outputs the result. That result is the effective policy
    that will be honored by policy checks.

    :param output_file: The path of a file to output to. stdout used if None.
    :param exclude_deprecated: If to exclude deprecated policy rule entries,
                               defaults to False.
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

    for section in _sort_and_format_by_section(
            policies, include_help=False,
            exclude_deprecated=exclude_deprecated):
        output_file.write(section)

    if output_file != sys.stdout:
        output_file.close()


def _list_redundant(namespace):
    """Generate a list of configured policies which match defaults.

    This checks all policies loaded from policy files and checks to see if they
    match registered policies. If so then it is redundant to have them defined
    in a policy file and operators should consider removing them.
    """
    enforcer = _get_enforcer(namespace)
    # NOTE(bnemec): We don't want to see policy deprecation warnings in the
    # output of this tool. They tend to overwhelm the output that the user
    # actually cares about, and checking for deprecations isn't the purpose of
    # this tool.
    enforcer.suppress_deprecation_warnings = True
    # Ensure that files have been parsed
    enforcer.load_rules()

    for name, file_rule in enforcer.file_rules.items():
        reg_rule = enforcer.registered_rules.get(name)
        if reg_rule:
            if file_rule == reg_rule:
                print(reg_rule)


def _validate_policy(namespace):
    """Perform basic sanity checks on a policy file

    Checks for the following errors in the configured policy file:

    * A missing policy file
    * Rules which have invalid syntax
    * Rules which reference non-existent other rules
    * Rules which form a cyclical reference with another rule
    * Rules which do not exist in the specified namespace

    :param namespace: The name under which the oslo.policy enforcer is
                      registered.
    :returns: 0 if all policies validated correctly, 1 if not.
    """
    return_code = 0
    enforcer = _get_enforcer(namespace)
    # NOTE(bnemec): We don't want to see policy deprecation warnings in the
    # output of this tool. They tend to overwhelm the output that the user
    # actually cares about. If we check for deprecated rules in this tool,
    # we need to do it another way.
    enforcer.suppress_deprecation_warnings = True
    # Disable logging from the parser code. We'll be printing any errors we
    # find below.
    logging.disable(logging.ERROR)
    # Ensure that files have been parsed
    enforcer.load_rules()

    if enforcer._informed_no_policy_file:
        print('Configured policy file "%s" not found' % enforcer.policy_file)
        # If the policy file is completely missing then the rest of our checks
        # don't make sense.
        return 1

    # Re-enable logging so we get messages for things like cyclical references
    logging.disable(logging.NOTSET)
    result = enforcer.check_rules()
    if not result:
        print('Invalid rules found')
        return_code = 1

    # TODO(bnemec): Allow this to handle policy_dir
    with open(cfg.CONF.oslo_policy.policy_file) as f:
        unparsed_policies = yaml.safe_load(f.read())
    for name, file_rule in enforcer.file_rules.items():
        reg_rule = enforcer.registered_rules.get(name)
        if reg_rule is None:
            print('Unknown rule found in policy file:', name)
            return_code = 1
        # If a rule has invalid syntax it will be forced to '!'. If the literal
        # rule from the policy file isn't '!' then this means there was an
        # error parsing it.
        if str(enforcer.rules[name]) == '!' and unparsed_policies[name] != '!':
            print('Failed to parse rule:', unparsed_policies[name])
            return_code = 1
    return return_code


def _convert_policy_json_to_yaml(namespace, policy_file, output_file=None):
    with open(policy_file) as rule_data:
        file_policies = jsonutils.loads(rule_data.read())

    yaml_format_rules = []
    default_policies = get_policies_dict(namespace)
    for section in sorted(default_policies):
        default_rules = default_policies[section]
        for default_rule in default_rules:
            if default_rule.name not in file_policies:
                continue
            file_rule_check_str = file_policies.pop(default_rule.name)
            # Some rules might be still RuleDefault object so let's prepare
            # empty 'operations' list and rule name as description for
            # those.
            operations = [{
                'method': '',
                'path': ''
            }]
            if hasattr(default_rule, 'operations'):
                operations = default_rule.operations
            # Converting JSON file rules to DocumentedRuleDefault rules so
            # that we can convert the JSON file to YAML including
            # descriptions which is what 'oslopolicy-sample-generator'
            # tool does.
            file_rule = policy.DocumentedRuleDefault(
                default_rule.name,
                file_rule_check_str,
                default_rule.description or default_rule.name,
                operations,
                default_rule.deprecated_rule,
                default_rule.deprecated_for_removal,
                default_rule.deprecated_reason,
                default_rule.deprecated_since,
                scope_types=default_rule.scope_types)
            if file_rule == default_rule:
                rule_text = _format_rule_default_yaml(
                    file_rule, add_deprecated_rules=False)
            else:
                # NOTE(gmann): If json file rule is not same as default
                # means rule is overridden then do not comment out it in
                # yaml file.
                rule_text = _format_rule_default_yaml(
                    file_rule, comment_rule=False,
                    add_deprecated_rules=False)
            yaml_format_rules.append(rule_text)

    extra_rules_text = ("# WARNING: Below rules are either deprecated rules\n"
                        "# or extra rules in policy file, it is strongly\n"
                        "# recommended to switch to new rules.\n")
    # NOTE(gmann): If policy json file still using the deprecated rules which
    # will not be present in default rules list. Or it can be case of any
    # extra rule (old rule which is now removed) present in json file.
    # so let's keep these as it is (not commented out) to avoid breaking
    # existing deployment.
    if file_policies:
        yaml_format_rules.append(extra_rules_text)
    for file_rule, check_str in file_policies.items():
        rule_text = ('"%(name)s": "%(check_str)s"\n' %
                     {'name': file_rule,
                      'check_str': check_str})
        yaml_format_rules.append(rule_text)

    if output_file:
        with open(output_file, 'w') as fh:
            fh.writelines(yaml_format_rules)
    else:
        sys.stdout.writelines(yaml_format_rules)


def on_load_failure_callback(*args, **kwargs):
    raise


def _check_for_namespace_opt(conf):
    # NOTE(bnemec): This opt is required, but due to lp#1849518 we need to
    # make it optional while our consumers migrate to the new method of
    # parsing cli args. Making the arg itself optional and explicitly checking
    # for it in the tools will allow us to migrate projects without breaking
    # anything. Once everyone has migrated, we can make the arg required again
    # and remove this check.
    if conf.namespace is None:
        raise cfg.RequiredOptError('namespace', 'DEFAULT')


def generate_sample(args=None, conf=None):
    logging.basicConfig(level=logging.WARN)
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + RULE_OPTS)
    conf.register_opts(GENERATOR_OPTS + RULE_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    _generate_sample(conf.namespace, output_file=conf.output_file,
                     output_format=conf.format,
                     exclude_deprecated=conf.exclude_deprecated)


def generate_policy(args=None):
    logging.basicConfig(level=logging.WARN)
    conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + ENFORCER_OPTS)
    conf.register_opts(GENERATOR_OPTS + ENFORCER_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    _generate_policy(conf.namespace, conf.output_file,
                     conf.exclude_deprecated)


def _upgrade_policies(policies, default_policies):
    old_policies_keys = list(policies.keys())
    for section in sorted(default_policies.keys()):
        rule_defaults = default_policies[section]
        for rule_default in rule_defaults:
            if (rule_default.deprecated_rule and
                    rule_default.deprecated_rule.name in old_policies_keys):
                policies[rule_default.name] = policies.pop(
                    rule_default.deprecated_rule.name)
                LOG.info('The name of policy %(old_name)s has been upgraded to'
                         '%(new_name)',
                         {'old_name': rule_default.deprecated_rule.name,
                          'new_name': rule_default.name})


def upgrade_policy(args=None, conf=None):
    logging.basicConfig(level=logging.WARN)
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + RULE_OPTS + UPGRADE_OPTS)
    conf.register_opts(GENERATOR_OPTS + RULE_OPTS + UPGRADE_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    with open(conf.policy) as input_data:
        policies = policy.parse_file_contents(input_data.read())
    default_policies = get_policies_dict(conf.namespace)

    _upgrade_policies(policies, default_policies)

    if conf.output_file:
        with open(conf.output_file, 'w') as fh:
            if conf.format == 'yaml':
                yaml.safe_dump(policies, fh, default_flow_style=False)
            elif conf.format == 'json':
                LOG.warning(policy.WARN_JSON)
                jsonutils.dump(policies, fh, indent=4)
    else:
        if conf.format == 'yaml':
            sys.stdout.write(yaml.safe_dump(policies,
                                            default_flow_style=False))
        elif conf.format == 'json':
            LOG.warning(policy.WARN_JSON)
            sys.stdout.write(jsonutils.dumps(policies, indent=4))


def list_redundant(args=None):
    logging.basicConfig(level=logging.WARN)
    conf = cfg.CONF
    conf.register_cli_opts(ENFORCER_OPTS)
    conf.register_opts(ENFORCER_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    _list_redundant(conf.namespace)


def validate_policy(args=None):
    logging.basicConfig(level=logging.WARN)
    conf = cfg.CONF
    conf.register_cli_opts(ENFORCER_OPTS)
    conf.register_opts(ENFORCER_OPTS)
    conf(args)
    sys.exit(_validate_policy(conf.namespace))


def convert_policy_json_to_yaml(args=None, conf=None):
    logging.basicConfig(level=logging.WARN)
    # Allow the caller to pass in a local conf object for unit testing
    if conf is None:
        conf = cfg.CONF
    conf.register_cli_opts(GENERATOR_OPTS + CONVERT_OPTS)
    conf.register_opts(GENERATOR_OPTS + CONVERT_OPTS)
    conf(args)
    _check_for_namespace_opt(conf)
    _convert_policy_json_to_yaml(conf.namespace, conf.policy_file,
                                 conf.output_file)
