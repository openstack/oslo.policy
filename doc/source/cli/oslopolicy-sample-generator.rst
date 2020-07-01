===========================
oslopolicy-sample-generator
===========================

.. program:: oslopolicy-sample-generator

Synopsis
--------

::

   oslopolicy-sample-generator [-h] [--config-dir DIR]
                               [--config-file PATH] [--format FORMAT]
                               [--namespace NAMESPACE]
                               [--output-file OUTPUT_FILE]


Description
-----------

The ``oslopolicy-sample-generator`` command can be used to generate a sample
policy file based on the default policies in a given namespace. This tool
requires a namespace to query for policies and supports output in JSON or YAML.

Options
-------

.. include:: common/default-opts.rst

.. include:: common/rule-opts.rst

.. include:: common/generator-opts.rst

Examples
--------

To generate sample policies for a namespace called ``keystone``:

.. code-block:: bash

   oslopolicy-sample-generator --namespace keystone

To generate sample policies in JSON use:

.. code-block:: bash

   oslopolicy-sample-generator --namespace keystone --format json

To generate a sample policy file and output directly to a file:

.. code-block:: bash

   oslopolicy-sample-generator --namespace keystone \
     --format yaml \
     --output-file keystone-policy.yaml

Use the following to generate help text for additional options and arguments
supported by ``oslopolicy-sample-generator``:

.. code-block:: bash

   oslopolicy-sample-generator --help

See Also
--------

:program:`oslopolicy-policy-generator`, :program:`oslopolicy-list-redundant`,
:program:`oslopolicy-checker`
