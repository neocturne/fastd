# Helper script for building fastd-android and its dependencies
#!/bin/bash

set -e

if [ x${PWD##*/} == xdoc ]; then
    echo "Warning: it seems you're currently in the doc/ folder. This script needs to run under the top folder of fastd source code."
    echo "See README-Android.md for more info."
    exit 1
fi

echo "This script downloads and builds dependencies for fastd-android, as well as fastd-android itself."
echo "Make sure you have these packages installed:"
echo "  * Android NDK r10d or newer"
echo "  * for Debian/Ubuntu: sudo apt-get install curl build-eseentials automake bison cmake git libtool pkg-config"
echo "    - Ubuntu 12.04 users need to grab cmake 2.8.9 or newer. See README-Android.md for more info."
echo "  * for Mac OS X: brew install automake libtool cmake bison"
echo "Hit ctrl-c now if you don't have all needed stuff yet."
read

SODIUM_VER=1.0.8
UECC_VER=7
LIBUECC_DOWNLOAD_ID=85
LIBSODIUM_PATH=libsodium-${SODIUM_VER}
LIBUECC_PATH=libuecc-${UECC_VER}

ANDROID_NATIVE_LEVEL=16

if [ x$ANDROID_NDK_HOME = x ]; then
    echo "Set ANDROID_NDK_HOME first"; exit 1;
fi

mkdir -p android

pushd android > /dev/null
WORK_DIR=${PWD}

mkdir -p pkgconfig/armeabi-v7a pkgconfig/x86

if [ -d "${LIBSODIUM_PATH}" ]; then
    echo "It seems you already have libsodium downloaded.";
else
    echo "Downloading libsodium ${SODIUM_VER}..."
    curl -L https://github.com/jedisct1/libsodium/releases/download/${SODIUM_VER}/libsodium-${SODIUM_VER}.tar.gz | tar zxf - || exit 1
fi

pushd ${LIBSODIUM_PATH} > /dev/null

echo "Patching libsodium build scripts..."
sed -i -e 's/--enable-minimal//' dist-build/android-build.sh

if [ ! -d "libsodium-android-armv7-a" ]; then
    NDK_PLATFORM=android-${ANDROID_NATIVE_LEVEL} dist-build/android-armv7-a.sh || exit 2
    # for static link using cmake
    rm libsodium-android-armv7-a/lib/libsodium.so
    cp libsodium-android-armv7-a/lib/pkgconfig/libsodium.pc ../pkgconfig/armeabi-v7a/
fi
if [ ! -d "libsodium-android-i686" ]; then
    NDK_PLATFORM=android-${ANDROID_NATIVE_LEVEL} dist-build/android-x86.sh || exit 2
    # for static link using cmake
    rm libsodium-android-i686/lib/libsodium.so
    cp libsodium-android-i686/lib/pkgconfig/libsodium.pc ../pkgconfig/x86/
fi
popd > /dev/null

if [ -d "android-cmake" ]; then
    echo "It seems you already have android-cmake downloaded.";
else
    echo "Downloading android-cmake"
    git clone https://github.com/taka-no-me/android-cmake.git;
fi
CMAKE_TOOLCHAIN=${WORK_DIR}/android-cmake/android.toolchain.cmake
ANDROID_CMAKE="cmake -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN}"
echo ">> android-cmake ready."

CMAKE_COMMON_DEFS="-DCMAKE_BUILD_TYPE=Release -DANDROID_NDK=${ANDROID_NDK_HOME} -DANDROID_NATIVE_API_LEVEL=${ANDROID_NATIVE_LEVEL}"

if [ -d "${LIBUECC_PATH}" ]; then
    echo "It seems you already have libuecc downloaded.";
else
    curl -k -L https://projects.universe-factory.net/attachments/download/${LIBUECC_DOWNLOAD_ID}/libuecc-${UECC_VER}.tar.xz | tar Jxf - || exit 4
fi
for ARCH in armeabi-v7a x86; do
    BUILD_DIR=libuecc-${ARCH}
    if [ ! -d "${BUILD_DIR}" ]; then
        mkdir ${BUILD_DIR} && pushd ${BUILD_DIR} > /dev/null
        ${ANDROID_CMAKE} -DANDROID_ABI="${ARCH}" ${CMAKE_COMMON_DEFS} -DCMAKE_INSTALL_PREFIX=`pwd`/output ../${LIBUECC_PATH} || exit 5
        make && make install || exit 6
        # for static link using cmake
        rm output/lib/libuecc.so*
        cp output/lib/pkgconfig/libuecc.pc ../pkgconfig/${ARCH}
        popd > /dev/null
        echo ">> libuecc ${ARCH} built."
    fi
done

# detect HomeBrew installed bison for OS X
HOMEBREW_BISON_PATH="/usr/local/opt/bison/bin"
if [ -x "${HOMEBREW_BISON_PATH}/bison" ]; then
    USE_PATH=${HOMEBREW_BISON_PATH}:$PATH
else
    USE_PATH=$PATH
fi

FASTD_ANDROID_DEFS="-DWITH_CAPABILITIES=OFF -DWITH_STATUS_SOCKET=OFF -DWITH_CIPHER_AES128_CTR=FALSE -DWITH_METHOD_GENERIC_POLY1305=FALSE -DWITH_CMDLINE_COMMANDS=FALSE"

for ARCH in armeabi-v7a x86; do
    BUILD_DIR=fastd-${ARCH}
    mkdir -p ${BUILD_DIR}
    pushd ${BUILD_DIR} > /dev/null
    if [ ! -f "Makefile" ]; then

        PATH=${USE_PATH} PKG_CONFIG_LIBDIR=../pkgconfig/${ARCH} \
            ${ANDROID_CMAKE} \
            -DANDROID_ABI="${ARCH}" ${CMAKE_COMMON_DEFS} \
            ${FASTD_ANDROID_DEFS} \
            -DEXECUTABLE_OUTPUT_PATH=`pwd`/src -DCMAKE_INSTALL_PREFIX=`pwd` \
            ../.. || exit 7
    fi

    make install/strip && echo ">> fastd ${ARCH} build ready in build/${BUILD_DIR}/bin"
    popd > /dev/null
done

popd > /dev/null

