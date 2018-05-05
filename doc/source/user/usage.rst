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

Incorporating oslo.policy tooling
---------------------------------

The ``oslo.policy`` library offers a generator that projects can use to render
sample policy files, check for redundant rules or policies, among other things.
This is a useful tool not only for operators managing policies, but also
developers looking to automate documentation describing the projects default
policies.

This part of the document describes how you can incorporate these features into
your project. Let's assume we're working on an OpenStack-like project called
``foo``. Policies for this service are registered in code in a common module of
the project.

First, you'll need to expose a couple of entry points in the project's
``setup.cfg``::

    [entry_points]
    oslo.policy.policies =
        foo = foo.common.policies:list_rules

    oslo.policy.enforcer =
        foo = foo.common.policy:get_enforcer

The ``oslo.policy`` library uses the project namespace to call ``list_rules``,
which should return a list of ``oslo.policy`` objects, either instances of
``RuleDefault`` or ``DocumentedRuleDefault``.

The second entry point allows ``oslo.policy`` to generate complete policy from
overrides supplied by an existing policy file on disk. This is useful for
operators looking to supply a policy file to Horizon or for security compliance
complete with overrides important to that deployment. The ``get_enforcer``
method should return an instance of ``oslo.policy.policy:Enforcer``. The
information passed into the constructor of ``Enforcer`` should resolve any
overrides on disk. An example for project ``foo`` might look like the
following::

    from oslo_config import cfg
    from oslo_policy import policy

    from foo.common import policies

    CONF = cfg.CONF
    _ENFORCER = None

    def get_enforcer():
        CONF([], project='foo')
        global _ENFORCER
        if not _ENFORCER:
            _ENFORCER = policy.Enforcer(CONF)
            _ENFORCER.register_defaults(policies.list_rules())
        return _ENFORCER

Please note that if you're incorporating this into a project that already uses
``oslo.policy`` in some form or fashion, this might need to be changed to fit
that project's structure accordingly.

Next, you can create a configuration file for generating policies specifically
for project ``foo``. This file could be called ``foo-policy-generator.conf``
and it can be kept under version control within the project::

    [DEFAULT]
    output_file = etc/foo/policy.yaml.sample
    namespace = foo

If project ``foo`` uses tox, this makes it easier to create a specific tox
environment for generating sample configuration files in ``tox.ini``::

    [testenv:genpolicy]
    commands = oslopolicy-sample-generator --config-file etc/foo/policy.yaml.sample

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

* Projects can register policies as `DocumentedRuleDefault` objects, which
  require a method and path of the corresponding policy. This helps policy
  readers understand which path maps to a particular policy ultimately
  providing better documentation.

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

To provide more information about the policy, use the `DocumentedRuleDefault`
class::

    enforcer.register_default(
        policy.DocumentedRuleDefault(
            'identity:create_region',
            'rule:admin_required',
            'helpful text',
            [{'path': '/regions/{region_id}', 'method': 'POST'}]
        )
    )

The `DocumentedRuleDefault` class inherits from the `RuleDefault`
implementation, but it must be supplied with the `description` attribute in
order to be used. In addition, the `DocumentedRuleDefault` class requires a new
`operations` attributes that is a list of dictionaries. Each dictionary must
have a `path` and a `method` key. The `path` should map to the path used to
interact with the resource the policy protects. The `method` should be the HTTP
verb corresponding to the `path`. The list of `operations` can be supplied with
multiple dictionaries if the policy is used to protect multiple paths.

Setting scope
-------------

The `RuleDefault` and `DocumentedRuleDefault` objects have an attribute
dedicated to the intended scope of the operation called `scope_types`. This
attribute can only be set at rule definition and never overridden via a policy
file. This variable is designed to save the scope at which a policy should
operate. During enforcement, the information in `scope_types` is compared to
the scope of the token used in the request.

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

If output_file is omitted the sample file will be sent to stdout.

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

If output_file is omitted the file will be sent to stdout.

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
