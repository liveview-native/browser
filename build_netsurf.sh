#!/bin/zsh

export OS=iphonesimulator
export ARCH=arm64
export SDK=$(xcrun --sdk $OS --show-sdk-path)
export CC=$(xcrun --sdk "$SDK" -f clang)
export CXX=$(xcrun --sdk "$SDK" -f clang++)
export CPP="$CC -E"
export AR="$(xcrun --sdk "$SDK" -f ar)"
export RANLIB="$(xcrun --sdk "$SDK" -f ranlib)"
export CFLAGS="-isysroot \"$SDK\" -arch $ARCH -mios-simulator-version-min=16.0"
export LDFLAGS="-isysroot \"$SDK\" -arch $ARCH -mios-simulator-version-min=16.0"
export MAKE="make CC=$CC AR=$AR RANLIB=$RANLIB"
export CMAKE="cmake -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=$ARCH -DCMAKE_OSX_SYSROOT=\"$SDK\" -DCMAKE_OSX_DEPLOYMENT_TARGET=16.0"
export AUTOCONF_FLAGS="--disable-shared --host=arm-apple-darwin CC=\"$CC\" CXX=\"$CXX\" CPP=\"$CPP\" AR=\"$AR\" RANLIB=\"$RANLIB\" CFLAGS=\"$CFLAGS\" CPPFLAGS=\"$CFLAGS\" LDFLAGS=\"$LDFLAGS\""
export SKIP_EXAMPLES=1
make install-netsurf