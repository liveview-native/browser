```sh
make get-v8
OS=ios make build-v8

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
make install

SDK=$(xcrun --sdk iphonesimulator --show-sdk-path) zig build -Dtarget=aarch64-ios-simulator -Dcpu=apple_m1 --release=safe
```

```sh
make get-v8
OS=ios make build-v8

swiftly use main-snapshot-2025-10-16

export OS=android
export ARCH=aarch64
export SDK=$(realpath ~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/sysroot)
export CC=$(realpath ~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android29-clang)
export CXX=$(realpath ~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android29-clang++)
export CPP="$CC -E"
export AR=$(realpath ~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar)
export RANLIB=echo
export CFLAGS="-isysroot \"$SDK\" -fPIC"
export LDFLAGS="-isysroot \"$SDK\""
export MAKE="make CC=$CC AR=$AR RANLIB=$RANLIB"
export CMAKE="cmake -DCMAKE_SYSTEM_NAME=Android -DANDROID_ABI=arm64-v8a -DCMAKE_TOOLCHAIN_FILE=$(realpath ~/android-ndk/android-ndk-r27d/build/cmake/android.toolchain.cmake)"
export AUTOCONF_FLAGS="--disable-shared --host=arm-apple-darwin CC=\"$CC\" CXX=\"$CXX\" CPP=\"$CPP\" AR=\"$AR\" RANLIB=\"$RANLIB\" CFLAGS=\"$CFLAGS\" CPPFLAGS=\"$CFLAGS\" LDFLAGS=\"$LDFLAGS\""
export SKIP_EXAMPLES=1
make install

# modify 'vendor/netsurf/share/netsurf-buildsystem/makefiles/Makefile.tools:419'
#  ifeq ($(word 1,$(ccvsn)),Android)
#    # Android
#    toolchain := clang
#  endif

SDK=$(realpath ~/Library/org.swift.swiftpm/swift-sdks/swift-DEVELOPMENT-SNAPSHOT-2025-10-16-a-android-0.1.artifactbundle/swift-android/ndk-sysroot) zig build -Dtarget=aarch64-ios-simulator -Dcpu=apple_m1 --release=safe
```