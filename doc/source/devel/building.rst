Building fastd
==============

Dependencies
~~~~~~~~~~~~

* libuecc (>= v6; >= v7 recommended; developed together with fastd)
* libsodium or NaCl (for most crypto methods)
* bison (>= 2.5)
* pkg-config

Optional:

* libcap (if WITH_CAPABILITIES is enabled; Linux only; can be disabled if you don't need POSIX capability support)
* libjson-c (if WITH_STATUS_SOCKET is enabled)
* libssl (if ENABLE_OPENSSL is enabled; provides fast AES implementations)

Building
~~~~~~~~

fastd uses the CMake build system. The libuecc build works the same.

::

    # Get fastd (or use the release tarballs)
    git clone git://git.universe-factory.net/fastd

    # Create a build dir
    mkdir fastd-build
    cd fastd-build
    cmake ../fastd -DCMAKE_BUILD_TYPE=RELEASE # Set DEBUG instead of RELEASE if you plan to develop on fastd

    # Build fastd, binary can be found in the src subdir of the build dir
    make

    # Install in the system
    make install

CMake will fail if any of fastd's dependencies can't be found. The build can be configured with the ccmake tool
if it is installed (in package ``cmake-curses-gui`` on Debian).

CMake variables
~~~~~~~~~~~~~~~
There are a few more options besides ``CMAKE_BUILD_TYPE`` that can be given to cmake with ``-DVARIABLE=VALUE``:

* By default, fastd will try to build against libsodium. If you want to use NaCl instead, set ENABLE_LIBSODIUM=OFF
* If you have a recent enough toolchain (GCC 4.8 or higher recommended), you can enable link-time optimization with ENABLE_LTO=ON to get slightly better optimized binaries
* If you want to use LTO with a binutils version without linker plugin support, you need to use the GCC versions of ar, nm and ranlib by setting the following variables::

    CMAKE_AR=/usr/bin/gcc-ar
    CMAKE_NM=/usr/bin/gcc-nm
    CMAKE_RANLIB=/usr/bin/gcc-ranlib

* You can see all CMake options by calling ``ccmake .`` in the build directory after running cmake. Use the `t` key to toggle display between simple and advanced view and use `c` and then `g` to update the configuration after making changes in ccmake.
