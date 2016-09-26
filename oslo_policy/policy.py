# -*- coding: utf-8 -*-
#
# Copyright (c) 2012 OpenStack Foundation.
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

"""
Common Policy Engine Implementation

Policies are expressed as a target and an associated rule::

    "<target>": <rule>

The `target` is specific to the service that is conducting policy
enforcement.  Typically, the target refers to an API call.

For the `<rule>` part, see `Policy Rule Expressions`.

Policy Rule Expressions
~~~~~~~~~~~~~~~~~~~~~~~

Policy rules can be expressed in one of two forms: a string written in the new
policy language or a list of lists. The string format is preferred since it's
easier for most people to understand.

In the policy language, each check is specified as a simple "a:b" pair that is
matched to the correct class to perform that check:

 +--------------------------------+------------------------------------------+
 |            TYPE                |                SYNTAX                    |
 +================================+==========================================+
 |User's Role                     |              role:admin                  |
 +--------------------------------+------------------------------------------+
 |Rules already defined on policy |          rule:admin_required             |
 +--------------------------------+------------------------------------------+
 |Against URLs¹                   |         http://my-url.org/check          |
 +--------------------------------+------------------------------------------+
 |User attributes²                |    project_id:%(target.project.id)s      |
 +--------------------------------+------------------------------------------+
 |Strings                         |        - <variable>:'xpto2035abc'        |
 |                                |        - 'myproject':<variable>          |
 +--------------------------------+------------------------------------------+
 |                                |         - project_id:xpto2035abc         |
 |Literals                        |         - domain_id:20                   |
 |                                |         - True:%(user.enabled)s          |
 +--------------------------------+------------------------------------------+

¹URL checking must return ``True`` to be valid

²User attributes (obtained through the token): user_id, domain_id or project_id

Conjunction operators ``and`` and ``or`` are available, allowing for more
expressiveness in crafting policies. For example::

    "role:admin or (project_id:%(project_id)s and role:projectadmin)"

The policy language also has the ``not`` operator, allowing a richer
policy rule::

    "project_id:%(project_id)s and not role:dunce"

Operator precedence is below:

 +------------+-------------+-------------+
 | PRECEDENCE |     TYPE    | EXPRESSION  |
 +============+=============+=============+
 |      4     |  Grouping   |    (...)    |
 +------------+-------------+-------------+
 |      3     | Logical NOT |   not ...   |
 +------------+-------------+-------------+
 |      2     | Logical AND | ... and ... |
 +------------+-------------+-------------+
 |      1     | Logical OR  | ... or ...  |
 +------------+-------------+-------------+

Operator with larger precedence number precedes others with smaller numbers.

In the list-of-lists representation, each check inside the innermost
list is combined as with an "and" conjunction -- for that check to pass,
all the specified checks must pass.  These innermost lists are then
combined as with an "or" conjunction. As an example, take the following
rule, expressed in the list-of-lists representation::

    [["role:admin"], ["project_id:%(project_id)s", "role:projectadmin"]]

Finally, two special policy checks should be mentioned; the policy
check "@" will always accept an access, and the policy check "!" will
always reject an access.  (Note that if a rule is either the empty
list (``[]``) or the empty string (``""``), this is equivalent to the "@"
policy check.)  Of these, the "!" policy check is probably the most useful,
as it allows particular rules to be explicitly disabled.

Generic Checks
~~~~~~~~~~~~~~

A `generic` check is used to perform matching against attributes that are sent
along with the API calls.  These attributes can be used by the policy engine
(on the right side of the expression), by using the following syntax::

    <some_attribute>:%(user.id)s

The value on the right-hand side is either a string or resolves to a
string using regular Python string substitution.  The available attributes
and values are dependent on the program that is using the common policy
engine.

All of these attributes (related to users, API calls, and context) can be
checked against each other or against constants.  It is important to note
that these attributes are specific to the service that is conducting
policy enforcement.

Generic checks can be used to perform policy checks on the following user
attributes obtained through a token:

    - user_id
    - domain_id or project_id (depending on the token scope)
    - list of roles held for the given token scope

.. note:: Some resources which are exposed by the API do not support policy
enforcement by user_id, and only support policy enforcement by project_id.
Some global resources do not support policy enforcement by combination of
user_id and project_id.

For example, a check on the user_id would be defined as::

    user_id:<some_value>

Together with the previously shown example, a complete generic check
would be::

    user_id:%(user.id)s

It is also possible to perform checks against other attributes that
represent the credentials.  This is done by adding additional values to
the ``creds`` dict that is passed to the
:meth:`~oslo_policy.policy.Enforcer.enforce` method.

Special Checks
~~~~~~~~~~~~~~

Special checks allow for more flexibility than is possible using generic
checks.  The built-in special check types are ``role``, ``rule``, and ``http``
checks.

Role Check
^^^^^^^^^^

A ``role`` check is used to check if a specific role is present in the supplied
credentials.  A role check is expressed as::

    "role:<role_name>"

Rule Check
^^^^^^^^^^

A :class:`rule check <oslo_policy.policy.RuleCheck>` is used to
reference another defined rule by its name.  This allows for common
checks to be defined once as a reusable rule, which is then referenced
within other rules.  It also allows one to define a set of checks as a
more descriptive name to aid in readability of policy.  A rule check is
expressed as::

    "rule:<rule_name>"

The following example shows a role check that is defined as a rule,
which is then used via a rule check::

    "admin_required": "role:admin"
    "<target>": "rule:admin_required"

HTTP Check
^^^^^^^^^^

An ``http`` check is used to make an HTTP request to a remote server to
determine the results of the check.  The target and credentials are passed to
the remote server for evaluation.  The action is authorized if the remote
server returns a response of ``True``. An http check is expressed as::

    "http:<target URI>"

It is expected that the target URI contains a string formatting keyword,
where the keyword is a key from the target dictionary.  An example of an
http check where the `name` key from the target is used to construct the
URL is would be defined as::

    "http://server.test/%(name)s"

Registering New Special Checks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is also possible for additional special check types to be registered
using the :func:`~oslo_policy.policy.register` function.

The following classes can be used as parents for custom special check types:

    * :class:`~oslo_policy.policy.AndCheck`
    * :class:`~oslo_policy.policy.NotCheck`
    * :class:`~oslo_policy.policy.OrCheck`
    * :class:`~oslo_policy.policy.RuleCheck`

Default Rule
~~~~~~~~~~~~

A default rule can be defined, which will be enforced when a rule does
not exist for the target that is being checked.  By default, the rule
associated with the rule name of ``default`` will be used as the default
rule.  It is possible to use a different rule name as the default rule
by setting the ``policy_default_rule`` configuration setting to the
desired rule name.
"""

import logging
import os
import warnings

from oslo_config import cfg
from oslo_serialization import jsonutils
import six
import yaml

from oslo_policy import _cache_handler
from oslo_policy import _checks
from oslo_policy._i18n import _
from oslo_policy import _parser
from oslo_policy import opts


LOG = logging.getLogger(__name__)


register = _checks.register
"""Register a function or :class:`.Check` class as a policy check.

:param name: Gives the name of the check type, e.g., "rule",
             "role", etc.  If name is ``None``, a default check type
             will be registered.
:param func: If given, provides the function or class to register.
             If not given, returns a function taking one argument
             to specify the function or class to register,
             allowing use as a decorator.
"""

Check = _checks.Check
"""A base class to allow for user-defined policy checks.

:param kind: The kind of the check, i.e., the field before the ``:``.
:param match: The match of the check, i.e., the field after the ``:``.

"""

AndCheck = _checks.AndCheck
"""Implements the "and" logical operator.

A policy check that requires that a list of other checks all return True.

:param list rules: rules that will be tested.

"""

NotCheck = _checks.NotCheck
"""Implements the "not" logical operator.

A policy check that inverts the result of another policy check.

:param rule: The rule to negate.
:type rule: oslo_policy.policy.Check

"""

OrCheck = _checks.OrCheck
"""Implements the "or" operator.

A policy check that requires that at least one of a list of other
checks returns ``True``.

:param rules: A list of rules that will be tested.

"""

RuleCheck = _checks.RuleCheck
"""Recursively checks credentials based on the defined rules."""


class PolicyNotAuthorized(Exception):
    """Default exception raised for policy enforcement failure."""

    def __init__(self, rule, target, creds):
        msg = (_('%(rule)s on %(target)s by %(creds)s disallowed by policy') %
               {'rule': rule, 'target': target, 'creds': creds})
        super(PolicyNotAuthorized, self).__init__(msg)


class DuplicatePolicyError(Exception):
    def __init__(self, name):
        msg = _('Policy %(name)s is already registered') % {'name': name}
        super(DuplicatePolicyError, self).__init__(msg)


class PolicyNotRegistered(Exception):
    def __init__(self, name):
        msg = _('Policy %(name)s has not been registered') % {'name': name}
        super(PolicyNotRegistered, self).__init__(msg)


def parse_file_contents(data):
    """Parse the raw contents of a policy file.

    Parses the contents of a policy file which currently can be in either
    yaml or json format. Both can be parsed as yaml.

    :param data: A string containing the contents of a policy file.
    :returns: A dict of of the form {'policy_name1': 'policy1',
                                     'policy_name2': 'policy2,...}
    """
    try:
        parsed = yaml.safe_load(data)
    except yaml.YAMLError as e:
        # For backwards-compatibility, convert yaml error to ValueError,
        # which is what JSON loader raised.
        raise ValueError(six.text_type(e))
    return parsed


class Rules(dict):
    """A store for rules. Handles the default_rule setting directly."""

    @classmethod
    def load(cls, data, default_rule=None):
        """Allow loading of YAML/JSON rule data.

        .. versionadded:: 1.5.0

        """
        parsed_file = parse_file_contents(data)

        # Parse the rules
        rules = {k: _parser.parse_rule(v) for k, v in parsed_file.items()}

        return cls(rules, default_rule)

    @classmethod
    def load_json(cls, data, default_rule=None):
        """Allow loading of YAML/JSON rule data.

        .. warning::
            This method is deprecated as of the 1.5.0 release in favor of
            :meth:`load` and may be removed in the 2.0 release.

        """
        warnings.warn(
            'The load_json() method is deprecated as of the 1.5.0 release in '
            'favor of load() and may be removed in the 2.0 release.',
            DeprecationWarning)
        return cls.load(data, default_rule)

    @classmethod
    def from_dict(cls, rules_dict, default_rule=None):
        """Allow loading of rule data from a dictionary."""

        # Parse the rules stored in the dictionary
        rules = {k: _parser.parse_rule(v) for k, v in rules_dict.items()}

        return cls(rules, default_rule)

    def __init__(self, rules=None, default_rule=None):
        """Initialize the Rules store."""

        super(Rules, self).__init__(rules or {})
        self.default_rule = default_rule

    def __missing__(self, key):
        """Implements the default rule handling."""

        if isinstance(self.default_rule, dict):
            raise KeyError(key)

        # If the default rule isn't actually defined, do something
        # reasonably intelligent
        if not self.default_rule:
            raise KeyError(key)

        if isinstance(self.default_rule, _checks.BaseCheck):
            return self.default_rule

        # We need to check this or we can get infinite recursion
        if self.default_rule not in self:
            raise KeyError(key)

        elif isinstance(self.default_rule, six.string_types):
            return self[self.default_rule]

    def __str__(self):
        """Dumps a string representation of the rules."""

        # Start by building the canonical strings for the rules
        out_rules = {}
        for key, value in self.items():
            # Use empty string for singleton TrueCheck instances
            if isinstance(value, _checks.TrueCheck):
                out_rules[key] = ''
            else:
                out_rules[key] = str(value)

        # Dump a pretty-printed JSON representation
        return jsonutils.dumps(out_rules, indent=4)


class Enforcer(object):
    """Responsible for loading and enforcing rules.

    :param conf: A configuration object.
    :param policy_file: Custom policy file to use, if none is
                        specified, ``conf.oslo_policy.policy_file`` will be
                        used.
    :param rules: Default dictionary / Rules to use. It will be
                  considered just in the first instantiation. If
                  :meth:`load_rules` with ``force_reload=True``,
                  :meth:`clear` or :meth:`set_rules` with ``overwrite=True``
                  is called this will be overwritten.
    :param default_rule: Default rule to use, conf.default_rule will
                         be used if none is specified.
    :param use_conf: Whether to load rules from cache or config file.
    :param overwrite: Whether to overwrite existing rules when reload rules
                      from config file.
    """

    def __init__(self, conf, policy_file=None, rules=None,
                 default_rule=None, use_conf=True, overwrite=True):
        self.conf = conf
        opts._register(conf)

        self.default_rule = (default_rule or
                             self.conf.oslo_policy.policy_default_rule)
        self.rules = Rules(rules, self.default_rule)
        self.registered_rules = {}
        self.file_rules = {}

        self.policy_path = None

        self.policy_file = policy_file or self.conf.oslo_policy.policy_file
        self.use_conf = use_conf
        self.overwrite = overwrite
        self._loaded_files = []
        self._policy_dir_mtimes = {}
        self._file_cache = {}
        self._informed_no_policy_file = False

    def set_rules(self, rules, overwrite=True, use_conf=False):
        """Create a new :class:`Rules` based on the provided dict of rules.

        :param dict rules: New rules to use.
        :param overwrite: Whether to overwrite current rules or update them
                          with the new rules.
        :param use_conf: Whether to reload rules from cache or config file.
        """

        if not isinstance(rules, dict):
            raise TypeError(_('Rules must be an instance of dict or Rules, '
                            'got %s instead') % type(rules))
        self.use_conf = use_conf
        if overwrite:
            self.rules = Rules(rules, self.default_rule)
        else:
            self.rules.update(rules)

    def clear(self):
        """Clears :class:`Enforcer` contents.

        This will clear this instances rules, policy's cache, file cache
        and policy's path.
        """
        self.set_rules({})
        self.default_rule = None
        self.policy_path = None
        self._loaded_files = []
        self._policy_dir_mtimes = {}
        self._file_cache.clear()
        self.registered_rules = {}
        self.file_rules = {}
        self._informed_no_policy_file = False

    def load_rules(self, force_reload=False):
        """Loads policy_path's rules.

        Policy file is cached and will be reloaded if modified.

        :param force_reload: Whether to reload rules from config file.
        """

        if force_reload:
            self.use_conf = force_reload

        if self.use_conf:
            if not self.policy_path:
                try:
                    self.policy_path = self._get_policy_path(self.policy_file)
                except cfg.ConfigFilesNotFoundError:
                    if not self._informed_no_policy_file:
                        LOG.debug('The policy file %s could not be found.',
                                  self.policy_file)
                        self._informed_no_policy_file = True

            if self.policy_path:
                self._load_policy_file(self.policy_path, force_reload,
                                       overwrite=self.overwrite)
            for path in self.conf.oslo_policy.policy_dirs:
                try:
                    path = self._get_policy_path(path)
                except cfg.ConfigFilesNotFoundError:
                    continue
                if (force_reload or self._is_directory_updated(
                        self._policy_dir_mtimes, path)):
                    self._walk_through_policy_directory(path,
                                                        self._load_policy_file,
                                                        force_reload, False)

            for default in self.registered_rules.values():
                if default.name not in self.rules:
                    self.rules[default.name] = default.check

    @staticmethod
    def _is_directory_updated(cache, path):
        # Get the current modified time and compare it to what is in
        # the cache and check if the new mtime is greater than what
        # is in the cache
        mtime = 0
        if os.path.exists(path):
            # Make a list of all the files
            files = [path] + [os.path.join(path, file) for file in
                              os.listdir(path)]
            # Pick the newest one, let's use its time.
            mtime = os.path.getmtime(max(files, key=os.path.getmtime))
        cache_info = cache.setdefault(path, {})
        if mtime > cache_info.get('mtime', 0):
            cache_info['mtime'] = mtime
            return True
        return False

    @staticmethod
    def _walk_through_policy_directory(path, func, *args):
        if not os.path.isdir(path):
            raise ValueError('%s is not a directory' % path)
        # We do not iterate over sub-directories.
        policy_files = next(os.walk(path))[2]
        policy_files.sort()
        for policy_file in [p for p in policy_files if not p.startswith('.')]:
            func(os.path.join(path, policy_file), *args)

    def _record_file_rules(self, data, overwrite=False):
        """Store a copy of rules loaded from a file.

        It is useful to be able to distinguish between rules loaded from a file
        and those registered by a consuming service. In order to do so we keep
        a record of rules loaded from a file.

        :param data: The raw contents of a policy file.
        :param overwrite: If True clear out previously loaded rules.
        """
        if overwrite:
            self.file_rules = {}
        parsed_file = parse_file_contents(data)
        for name, check_str in parsed_file.items():
            self.file_rules[name] = RuleDefault(name, check_str)

    def _load_policy_file(self, path, force_reload, overwrite=True):
        reloaded, data = _cache_handler.read_cached_file(
            self._file_cache, path, force_reload=force_reload)
        if reloaded or not self.rules:
            rules = Rules.load(data, self.default_rule)
            self.set_rules(rules, overwrite=overwrite, use_conf=True)
            self._record_file_rules(data, overwrite)
            self._loaded_files.append(path)
            LOG.debug('Reloaded policy file: %(path)s', {'path': path})

    def _get_policy_path(self, path):
        """Locate the policy YAML/JSON data file/path.

        :param path: It's value can be a full path or related path. When
                     full path specified, this function just returns the full
                     path. When related path specified, this function will
                     search configuration directories to find one that exists.

        :returns: The policy path

        :raises: ConfigFilesNotFoundError if the file/path couldn't
                 be located.
        """
        policy_path = self.conf.find_file(path)

        if policy_path:
            return policy_path

        raise cfg.ConfigFilesNotFoundError((path,))

    def enforce(self, rule, target, creds, do_raise=False,
                exc=None, *args, **kwargs):
        """Checks authorization of a rule against the target and credentials.

        :param rule: The rule to evaluate.
        :type rule: string or :class:`BaseCheck`
        :param dict target: As much information about the object being operated
                            on as possible.
        :param dict creds: As much information about the user performing the
                           action as possible.
        :param do_raise: Whether to raise an exception or not if check
                        fails.
        :param exc: Class of the exception to raise if the check fails.
                    Any remaining arguments passed to :meth:`enforce` (both
                    positional and keyword arguments) will be passed to
                    the exception class. If not specified,
                    :class:`PolicyNotAuthorized` will be used.

        :return: ``False`` if the policy does not allow the action and `exc` is
                 not provided; otherwise, returns a value that evaluates to
                 ``True``.  Note: for rules using the "case" expression, this
                 ``True`` value will be the specified string from the
                 expression.
        """

        self.load_rules()

        # Allow the rule to be a Check tree
        if isinstance(rule, _checks.BaseCheck):
            result = rule(target, creds, self)
        elif not self.rules:
            # No rules to reference means we're going to fail closed
            result = False
        else:
            try:
                # Evaluate the rule
                result = self.rules[rule](target, creds, self)
            except KeyError:
                LOG.debug('Rule [%s] does not exist', rule)
                # If the rule doesn't exist, fail closed
                result = False

        # If it is False, raise the exception if requested
        if do_raise and not result:
            if exc:
                raise exc(*args, **kwargs)

            raise PolicyNotAuthorized(rule, target, creds)

        return result

    def register_default(self, default):
        """Registers a RuleDefault.

        Adds a RuleDefault to the list of registered rules. Rules must be
        registered before using the Enforcer.authorize method.

        :param default: A RuleDefault object to register.
        """
        if default.name in self.registered_rules:
            raise DuplicatePolicyError(default.name)

        self.registered_rules[default.name] = default

    def register_defaults(self, defaults):
        """Registers a list of RuleDefaults.

        Adds each RuleDefault to the list of registered rules. Rules must be
        registered before using the Enforcer.authorize method.

        :param default: A list of RuleDefault objects to register.
        """
        for default in defaults:
            self.register_default(default)

    def authorize(self, rule, target, creds, do_raise=False,
                  exc=None, *args, **kwargs):
        """A wrapper around 'enforce' that checks for policy registration.

        To ensure that a policy being checked has been registered this method
        should be used rather than enforce. By doing so a project can be sure
        that all of it's used policies are registered and therefore available
        for sample file generation.

        The parameters match the enforce method and a description of them can
        be found there.
        """
        if rule not in self.registered_rules:
            raise PolicyNotRegistered(rule)
        return self.enforce(rule, target, creds, do_raise, exc,
                            *args, **kwargs)


class RuleDefault(object):
    """A class for holding policy definitions.

    It is required to supply a name and value at creation time. It is
    encouraged to also supply a description to assist operators.

    :param name: The name of the policy. This is used when referencing it
                 from another rule or during policy enforcement.
    :param check_str: The policy. This is a string  defining a policy that
                      conforms to the policy language outlined at the top of
                      the file.
    :param description: A plain text description of the policy. This will be
                        used to comment sample policy files for use by
                        deployers.
    """
    def __init__(self, name, check_str, description=None):
        self.name = name
        self.check_str = check_str
        self.check = _parser.parse_rule(check_str)
        self.description = description

    def __str__(self):
        return '"%(name)s": "%(check_str)s"' % {'name': self.name,
                                                'check_str': self.check_str}

    def __eq__(self, other):
        """Equality operator.

        All check objects have a stable string representation. It is used for
        comparison rather than check_str because multiple check_str's may parse
        to the same check object. For instance '' and '@' are equivalent and
        the parsed rule string representation for both is '@'.

        The description does not play a role in the meaning of the check so it
        is not considered for equality.
        """
        # Name should match, check should match, and class should be equivalent
        # or one should be a subclass of the other.
        if (self.name == other.name and
                str(self.check) == str(other.check) and
                (isinstance(self, other.__class__) or
                 isinstance(other, self.__class__))):
            return True
        return False
