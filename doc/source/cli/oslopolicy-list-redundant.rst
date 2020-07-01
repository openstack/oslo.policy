=========================
oslopolicy-list-redundant
=========================

.. program:: oslopolicy-list-redundant

Synopsis
--------

::

  oslopolicy-list-redundant [-h] [--config-dir DIR] [--config-file PATH]
                            [--namespace NAMESPACE]

Description
-----------

The ``oslopolicy-list-redundant`` tool is useful for detecting policies that
are specified in policy files that are the same as the defaults provided by the
service. Operators can use this tool to find policies that they can remove from
their policy files, making maintenance easier.

This tool assumes a policy file containing overrides exists and is specified
through configuration.

Options
-------

.. include:: common/default-opts.rst

.. include:: common/enforcer-opts.rst

Examples
--------

To list redundant default policies:

.. code-block:: bash

   oslopolicy-list-redundant --namespace keystone --config-dir /etc/keystone

For more information regarding the options supported by this tool:

.. code-block:: bash

   oslopolicy-list-redundant --help

See Also
--------

:program:`oslopolicy-sample-generator`, :program:`oslopolicy-policy-generator`,
:program:`oslopolicy-checker`
