# -*- coding: utf-8 -*-
# Copyright (C) 2020 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.extlinks',
    'sphinxcontrib.apidoc',
    'openstackdocstheme',
    'oslo_config.sphinxext',
]

# openstackdocstheme options
openstackdocs_repo_name = 'openstack/oslo.policy'
openstackdocs_bug_project = 'oslo.policy'
openstackdocs_bug_tag = ''

# autodoc generation is a bit aggressive and a nuisance when doing heavy
# text edit cycles.
# execute "export SPHINX_DEBUG=1" in your terminal to disable

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
copyright = '2014-2020, OpenStack Foundation'
source_tree = 'https://opendev.org/openstack/oslo.policy/src/branch/master'

# If true, '()' will be appended to :func: etc. cross-reference text.
add_function_parentheses = True

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
add_module_names = True

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'native'

# A list of ignored prefixes for module index sorting.
modindex_common_prefix = ['oslo_policy.']

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  Major themes that come with
# Sphinx are currently 'default' and 'sphinxdoc'.
html_theme = 'openstackdocs'

# -- Options for man page output ---------------------------------------------

# Grouping the document tree for man pages.
# List of tuples 'sourcefile', 'target', 'title', 'Authors name', 'manual'

_man_pages = [
    (
        'oslopolicy-checker',
        'Check policy against the OpenStack Identity API access information.',
    ),
    (
        'oslopolicy-list-redundant',
        'Detect policies that are specified in policy files that are the same '
        'as the defaults provided by the service',
    ),
    (
        'oslopolicy-policy-generator',
        'Generate a policy file that shows the effective policy in use',
    ),
    (
        'oslopolicy-sample-generator',
        'Generate a sample policy file based on the default policies in a '
        'given namespace',
    ),
]

man_pages = [
    (f'cli/{name}', name, description, 'OpenStack Community', 1)
    for name, description in _man_pages
]

# -- sphinx.ext.extlinks configuration ---------------------------------------

extlinks = {
    'example': (source_tree + '/oslo_policy/%s', ''),
}

# -- sphinxcontrib.apidoc configuration --------------------------------------

apidoc_module_dir = '../../oslo_policy'
apidoc_output_dir = 'reference/api'
apidoc_excluded_paths = [
    'tests',
]
