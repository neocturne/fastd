Building fastd
==============

Dependencies
~~~~~~~~~~~~

* libuecc (>= v6; >= v7 recommended; developed together with fastd)
* libsodium or NaCl (for most crypto methods)
* bison (>= 2.6)
* pkg-config

Optional:

* libcap (if ``capabilities`` is enabled; Linux only; can be disabled if you don't need POSIX capability support)
* libmnl (for L2TP offload support; Linux only)
* libjson-c (if ``status_socket`` is enabled)
* libssl (if ``cipher_aes128-ctr`` is enabled)

Building
~~~~~~~~

Starting with v20, fastd uses the Meson build system.

::

    # Get fastd (or use the release tarballs)
    git clone https://github.com/neocturne/fastd.git

    # Set up a build dir
    meson setup fastd fastd-build -Dbuildtype=release
    cd fastd-build

    # Build fastd, binary can be found in the src subdir of the build dir
    ninja

    # Install in the system
    ninja install

Build settings
~~~~~~~~~~~~~~
The build can be configured using the command ``meson configure``; running it
without any additional arguments will show all available variables. Settings can
be passed to ``meson setup`` or ``meson configure`` using ``-DVARIABLE=VALUE``.

* By default, fastd will build against libsodium. If you want to use NaCl instead, add ``-Duse_nacl=true``
* If you have a recent enough toolchain (GCC 4.8 or higher recommended), you can enable link-time optimization by
  adding ``-Db_lto=true``
* Instead of using an installed version of libmnl, it is possible to build it
  as part of fastd itself by setting ``-Dlibmnl_builtin=true``. This is
  recommended for constrained targets only and not for regular Linux
  distributions.
