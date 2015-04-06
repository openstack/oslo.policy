======================
Command Line Interface
======================

Run the command line ``oslopolicy-checker`` to check policy against the
OpenStack Identity API access information.

Command-line arguments:

* ``--policy POLICY`` path to policy file.
* ``--access ACCESS`` path to access token file.
* ``--rule RULE`` (optional) rule to test.  If omitted, tests all rules.
* ``--is_admin IS_ADMIN`` (optional) set is_admin=True on the credentials.

Sample access tokens are provided in the ``sample_data`` directory.

Examples
--------

Test all of Nova's policy with an admin token

.. code-block:: bash

   tox -e venv -- oslopolicy-checker \
     --policy  /opt/stack/nova/etc/nova/policy.json
     --access sample_data/auth_v3_token_admin.json

Test the ``compute_extension:flavorextraspecs:index`` rule in Nova's policy
with the admin member token and ``is_admin`` set to ``True``

.. code-block:: bash

   tox -e venv -- oslopolicy-checker \
     --policy  /opt/stack/nova/etc/nova/policy.json \
     --access sample_data/auth_v3_token_admin.json \
     --is_admin=true --rule compute_extension:flavorextraspecs:index

Test the ``compute_extension:flavorextraspecs:index`` rule in Nova's policy
with the plain member token

.. code-block:: bash

   tox -e venv -- oslopolicy-checker \
     --policy  /opt/stack/nova/etc/nova/policy.json \
     --access sample_data/auth_v3_token_member.json \
     --rule compute_extension:flavorextraspecs:index
