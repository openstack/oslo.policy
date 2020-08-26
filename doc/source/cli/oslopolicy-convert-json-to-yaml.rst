===============================
oslopolicy-convert-json-to-yaml
===============================

.. program:: oslopolicy-convert-json-to-yaml

Synopsis
--------

::

   oslopolicy-convert-json-to-yaml [-h] [--config-dir DIR] [--config-file PATH]
                                   [--namespace NAMESPACE]
                                   [--policy-file POLICY_FILE]
                                   [--output-file OUTPUT_FILE]


Description
-----------

The ``oslopolicy-convert-json-to-yaml`` tool can be used to convert the JSON
format policy file to YAML format. It takes JSON formatted policy file as input
and convert it to a YAML formatted policy file similar to
``oslopolicy-sample-generator`` tool except keeping the overridden rule
as uncommented. It does the following:

* Comment out any rules that match the default from policy-in-code.
* Keep rules uncommented if rule is overridden.
* Does not auto add the deprecated rules in the file unless it not already
  present in the file.
* Keep any extra rules or already exist deprecated rules uncommented
  but at the end of the file with a warning text.

When to use:
~~~~~~~~~~~~

Oslo policy still support the policy file in JSON format, but that lead to
`multiple issues <https://specs.openstack.org/openstack/oslo-specs/specs/victoria/policy-json-to-yaml.html#problem-description>`_ .
One of the key issue came up while nova switched to the new policy with new
defaults and scope feature from keystone.
Refer `this bug <https://bugs.launchpad.net/nova/+bug/1875418>`_ for details.

In future release, oslo policy will remove the JSON formatted policy
file support and to have a smooth migration to YAML formatted policy file
you can use this tool to convert your existing JSON formatted file to YAML
file.

Options
-------

.. include:: common/default-opts.rst

.. include:: common/generator-opts.rst

.. include:: common/convert-opts.rst

Examples
--------

To convert a JSON policy file for a namespace called ``keystone``:

.. code-block:: bash

   oslopolicy-convert-json-to-yaml --namespace keystone \
     --policy-file keystone-policy.json

To convert a JSON policy file to yaml format directly to a file:

.. code-block:: bash

   oslopolicy-convert-json-to-yaml --namespace keystone \
     --policy-file keystone-policy.json \
     --output-file keystone-policy.yaml

Use the following to generate help text for additional options and arguments
supported by ``oslopolicy-convert-json-to-yaml``:

.. code-block:: bash

   oslopolicy-convert-json-to-yaml --help

See Also
--------

:program:`oslopolicy-sample-generator`, :program:`oslopolicy-policy-generator`, :program:`oslopolicy-upgrade`
