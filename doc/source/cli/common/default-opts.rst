.. option:: -h, --help

    Show help message and exit.

.. option:: --config-dir DIR

    Path to a config directory to pull ``*.conf`` files from. This file set is
    sorted, so as to provide a predictable parse order if individual options
    are overridden. The set is parsed after the file(s) specified via previous
    ``--config-file``, arguments hence overridden options in the directory
    take precedence.

    This option must be set from the command-line.

.. option:: --config-file PATH

    Path to a config file to use. Multiple config files can be specified, with
    values in later files taking precedence. Defaults to None. This option must
    be set from the command-line.
