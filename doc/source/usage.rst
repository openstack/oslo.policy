=======
 Usage
=======

To use oslo.policy in a project, import the relevant module. For
example::

    from oslo_policy import policy

Migrating to oslo.policy
========================

Applications using the incubated version of the policy code from Oslo aside
from changing the way the library is imported, may need to make some extra
changes.

Changes to Enforcer Initialization
----------------------------------

The ``oslo.policy`` library no longer assumes a global configuration object is
available. Instead the :py:class:`oslo_policy.policy.Enforcer` class has been
changed to expect the consuming application to pass in an ``oslo.config``
configuration object.

When using policy from oslo-incubator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    enforcer = policy.Enforcer(policy_file=_POLICY_PATH)

When using oslo.policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    from oslo_config import cfg
    CONF = cfg.CONF
    enforcer = policy.Enforcer(CONF, policy_file=_POLICY_PATH)

Registering policy defaults in code
===================================

A project can register policy defaults in their code which brings with it some
benefits.

* A deployer only needs to add a policy file if they wish to override the
  project defaults.

* Projects can use Enforcer.authorize to ensure that a policy check is being
  done against a registered policy. This can be used to ensure that all
  policies used are registered. The signature of Enforcer.authorize matches
  Enforcer.enforce.

* A sample policy file can be generated based on the registered policies
  rather than needing to manually maintain one.

* A policy file can be generated which is a merge of registered defaults and
  policies loaded from a file. This shows the effective policy in use.

* A list can be generated which contains policies defined in a file which match
  defaults registered in code. These are candidates for removal from the file
  in order to keep it small and understandable.

How to register
---------------

::

    from oslo_config import cfg
    CONF = cfg.CONF
    enforcer = policy.Enforcer(CONF, policy_file=_POLICY_PATH)

    base_rules = [
        policy.RuleDefault('admin_required', 'role:admin or is_admin:1',
                           description='Who is considered an admin'),
        policy.RuleDefault('service_role', 'role:service',
                           description='service role'),
    ]

    enforcer.register_defaults(base_rules)
    enforcer.register_default(policy.RuleDefault('identity:create_region',
                                                 'rule:admin_required',
                                                 description='helpful text'))

Sample file generation
----------------------

In setup.cfg of a project using oslo.policy::

    [entry_points]
    oslo.policy.policies =
        nova = nova.policy:list_policies

where list_policies is a method that returns a list of policy.RuleDefault
objects.

Run the oslopolicy-sample-generator script with some configuration options::

    oslopolicy-sample-generator --namespace nova --output-file policy-sample.yaml

or::

    oslopolicy-sample-generator --config-file policy-generator.conf

where policy-generator.conf looks like::

    [DEFAULT]
    output_file = policy-sample.yaml
    namespace = nova

If output_file is ommitted the sample file will be sent to stdout.

Merged file generation
----------------------

This will output a policy file which includes all registered policy defaults
and all policies configured with a policy file. This file shows the effective
policy in use by the project.

In setup.cfg of a project using oslo.policy::

    [entry_points]
    oslo.policy.enforcer =
        nova = nova.policy:get_enforcer

where get_enforcer is a method that returns a configured
oslo_policy.policy.Enforcer object. This object should be setup exactly as it
is used for actual policy enforcement, if it differs the generated policy file
may not match reality.

Run the oslopolicy-policy-generator script with some configuration options::

    oslopolicy-policy-generator --namespace nova --output-file policy-merged.yaml

or::

    oslopolicy-policy-generator --config-file policy-merged-generator.conf

where policy-merged-generator.conf looks like::

    [DEFAULT]
    output_file = policy-merged.yaml
    namespace = nova

If output_file is ommitted the file will be sent to stdout.

List of redundant configuration
-------------------------------

This will output a list of matches for policy rules that are defined in a
configuration file where the rule does not differ from a registered default
rule. These are rules that can be removed from the policy file with no change
in effective policy.

In setup.cfg of a project using oslo.policy::

    [entry_points]
    oslo.policy.enforcer =
        nova = nova.policy:get_enforcer

where get_enforcer is a method that returns a configured
oslo_policy.policy.Enforcer object. This object should be setup exactly as it
is used for actual policy enforcement, if it differs the generated policy file
may not match reality.

Run the oslopolicy-list-redundant script::

    oslopolicy-list-redundant --namespace nova

or::

    oslopolicy-list-redundant --config-file policy-redundant.conf

where policy-redundant.conf looks like::

    [DEFAULT]
    namespace = nova

Output will go to stdout.
