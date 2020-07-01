====================
oslopolicy-validator
====================

.. program:: oslopolicy-policy-validator

Synopsis
--------

::

  oslopolicy-policy-validator

Description
-----------

The ``oslopolicy-validator`` tool can be used to perform basic sanity checks
against a policy file. It will detect the following problems:

* A missing policy file
* Rules which have invalid syntax
* Rules which reference non-existent other rules
* Rules which form a cyclical reference with another rule
* Rules which do not exist in the specified namespace

This tool does very little validation of the content of the rules. Other tools,
such as ``oslopolicy-checker``, should be used to check that rules do what is
intended.

Options
-------

.. include:: common/default-opts.rst

.. include:: common/enforcer-opts.rst

Examples
--------

Validate the policy file used for Keystone:

.. code-block:: bash

   oslopolicy-validator --config-file /etc/keystone/keystone.conf --namespace keystone

Sample output from a failed validation::

   $ oslopolicy-validator --config-file keystone.conf --namespace keystone
   WARNING:oslo_policy.policy:Policies ['foo', 'bar'] are part of a cyclical reference.
   Invalid rules found
   Failed to parse rule: (role:admin and system_scope:all) or (role:foo and oken.domain.id:%(target.user.domain_id)s))
   Unknown rule found in policy file: foo
   Unknown rule found in policy file: bar

See Also
--------

:program:`oslopolicy-checker`
