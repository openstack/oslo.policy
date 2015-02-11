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

    from keystone import config
    CONF = config.CONF
    enforcer = policy.Enforcer(CONF, policy_file=_POLICY_PATH)
