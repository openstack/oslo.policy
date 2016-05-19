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

* More will be documented as capabilities are added.

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
