fastd for Android
=================

Runtime Requirements
--------------------
* Android 4.1+
* x86 / ARMv7a
  * NEON optimiazation is planned but not currently required
  * Not tested with x86\_64 or AArch64 but should work too

How to Build
------------
* Android NDK r10d+ (r10c or older versions won't work)
    * make sure ANDROID\_NDK\_HOME is set
* Ubuntu 12.04+
    * `sudo apt-get install build-essential automake bison cmake libtool pkg-config`
    * For Ubuntu **12.04**: cmake 2.8.7 won't work; get a newer version from https://launchpad.net/~kalakris/+archive/ubuntu/cmake
* or Mac OS X 10.10+ (older versions should work too)
    * Homebrew
    * `brew install automake libtool cmake bison`

Then run `doc/build-fastd-android.sh` from `fastd-android` folder. Be warned the script is not perfect; you may need to look into it should anything go wrong.

