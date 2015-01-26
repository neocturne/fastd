Building fastd
==============

Dependencies
~~~~~~~~~~~~

* libuecc (developed together with fastd)
* libsodium or NaCl (for most crypto methods)
* libcap (Linux only; can be disabled if you don't need POSIX capability support)
* Bison (>= 2.5)
* pkg-config

Optional:

* libssl (for fast AES implementations; OpenSSL support must be enabled during build)

Building
~~~~~~~~

fastd uses the CMake build system. The libuecc build works the same.

::

    # Get fastd (or use the release tarballs)
    git clone git://git.universe-factory.net/fastd

    # Create a build dir
    mkdir fastd-build
    cd fastd-build
    cmake ../fastd

    # Build fastd, binary can be found in the src subdir of the build dir
    make

    # Install in the system
    make install

CMake will fail if any of fastd's dependencies can't be found. The build can be configured with the ccmake tool
if it is installed (in package ``cmake-curses-gui`` on Debian).

CMake variables
~~~~~~~~~~~~~~~

There are a few option that can be given to cmake with ``-DVARIABLE=VALUE``:

* If you have a recent enough toolchain (GCC 4.8 or higher recommended), you can enable link-time optimization with ENABLE_LTO=ON to get slightly better optimized binaries
* By default, fastd will try to build against libsodium. If you want to use NaCl instead, set ENABLE_LIBSODIUM=OFF
* Use ENABLE_OPENSSL=ON/OFF to enable or disable compiling against OpenSSL
* If you have a toolchain without binutils plugin support (e.g. on Debian Wheezy), it is not enough to keep ENABLE_LTO disabled, in addition CMake must be told to use the standard `ar`, `ranlib` and `nm` implementation instead of the GCC-provided versions::

    CMAKE_AR=/usr/bin/ar
    CMAKE_RANLIB=/usr/bin/ranlib
    CMAKE_NM=/usr/bin/nm

* You can see all CMake options by calling ``ccmake .`` in the build directory after running cmake. Use the `t` key to toggle display between simple and advanced view and use `c` and then `g` to update the configuration after making changes in ccmake.
