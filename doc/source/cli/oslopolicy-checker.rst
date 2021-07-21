==================
oslopolicy-checker
==================

.. program:: oslopolicy-checker

Synopsis
--------

::

   oslopolicy-checker [-h] [--access ACCESS] [--config-dir DIR]
                      [--config-file PATH]
                      [--enforcer_config ENFORCER_CONFIG] [--is_admin]
                      [--nois_admin] [--policy POLICY] [--rule RULE]
                      [--target TARGET]

Description
-----------

The ``oslopolicy-checker`` command can be used to check policy against
the OpenStack Identity API access information. The access information is a
keystone token response from keystone's `authentication API
<https://docs.openstack.org/api-ref/identity/v3/#password-authentication-with-scoped-authorization>`_.

Options
-------

.. include:: common/default-opts.rst

.. option:: --access ACCESS

    Path to a file containing an OpenStack Identity API token response body in
    JSON format.

.. option:: --enforcer_config ENFORCER_CONFIG

    Configuration file for the oslopolicy-checker enforcer

.. option:: --is_admin

    Set ``is_admin=True`` on the credentials used for the evaluation.

.. option:: --nois_admin

    The inverse of ``--is_admin``

.. option:: --policy POLICY

    Path to a policy file.

.. option:: --rule RULE

    Rule to test.

.. option:: --target TARGET

    Path to a file containing custom target info in JSON format. This will be
    used to evaluate the policy with.

Examples
--------

Test all of Nova's policy with an admin token:

.. code-block:: bash

   oslopolicy-checker \
     --policy /opt/stack/nova/etc/nova/policy.json
     --access sample_data/auth_v3_token_admin.json

Test the ``compute_extension:flavorextraspecs:index`` rule in Nova's policy
with the admin member token and ``is_admin`` set to ``True``:

.. code-block:: bash

   oslopolicy-checker \
     --policy /opt/stack/nova/etc/nova/policy.json \
     --access sample_data/auth_v3_token_admin.json \
     --is_admin=true --rule compute_extension:flavorextraspecs:index

Test the ``compute_extension:flavorextraspecs:index`` rule in Nova's policy
with the plain member token:

.. code-block:: bash

   oslopolicy-checker \
     --policy /opt/stack/nova/etc/nova/policy.json \
     --access sample_data/auth_v3_token_member.json \
     --rule compute_extension:flavorextraspecs:index

See Also
--------

:program:`oslopolicy-sample-generator`, :program:`oslopolicy-policy-generator`,
:program:`oslopolicy-list-redundant`, :program:`oslopolicy-validator`
