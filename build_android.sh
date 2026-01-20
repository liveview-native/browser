SDK=$(realpath ~/Library/org.swift.swiftpm/swift-sdks/swift-DEVELOPMENT-SNAPSHOT-2025-10-16-a-android-0.1.artifactbundle/swift-android/ndk-sysroot) zig build -Dtarget=aarch64-linux-android --release=safe

# cp v8/out/android/release/obj/zig/libc_v8.a ~/AndroidStudioProjects/LightpandaTest/LightpandaRenderer/src/debug/jniLibs/arm64-v8a/libc_v8.a
cp include/lightpanda.h /Users/carson.katri/AndroidStudioProjects/LightpandaTest/LightpandaRenderer/src/main/swift/Sources/lightpanda/lightpanda.h

mkdir -p zig-out/o
cd zig-out/o
~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -x ../../vendor/libiconv/out/android-aarch64/lib/libiconv.a
~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -x ../../vendor/mimalloc/out/android-aarch64/lib/libmimalloc.a
~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -x ../../vendor/mimalloc/out/android-aarch64/lib/libmimalloc.a
~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -x ../../vendor/netsurf/out/android-aarch64/lib/libdom.a
~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -x ../../vendor/netsurf/out/android-aarch64/lib/libhubbub.a
~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -x ../../vendor/netsurf/out/android-aarch64/lib/libparserutils.a
~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -x ../../vendor/netsurf/out/android-aarch64/lib/libwapcaplet.a
~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -x ../../v8/out/android/release/obj/zig/libc_v8.a

~/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar -r ../lib/liblightpanda.a *.o

cp ../lib/liblightpanda.a ~/AndroidStudioProjects/LightpandaTest/LightpandaRenderer/src/debug/jniLibs/arm64-v8a/liblightpanda.a


/Users/carson.katri/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf: warning: '/Users/carson.katri/Documents/lightpanda/browser/zig-out/lib/liblightpanda.a': /Users/carson.katri/Documents/lightpanda/browser/vendor/libiconv/out/android-aarch64/lib/libiconv.a has an unsupported file type
/Users/carson.katri/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf: warning: '/Users/carson.katri/Documents/lightpanda/browser/zig-out/lib/liblightpanda.a': /Users/carson.katri/Documents/lightpanda/browser/vendor/mimalloc/out/android-aarch64/lib/libmimalloc.a has an unsupported file type
/Users/carson.katri/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf: warning: '/Users/carson.katri/Documents/lightpanda/browser/zig-out/lib/liblightpanda.a': /Users/carson.katri/Documents/lightpanda/browser/vendor/netsurf/out/android-aarch64/lib/libdom.a has an unsupported file type
/Users/carson.katri/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf: warning: '/Users/carson.katri/Documents/lightpanda/browser/zig-out/lib/liblightpanda.a': /Users/carson.katri/Documents/lightpanda/browser/vendor/netsurf/out/android-aarch64/lib/libhubbub.a has an unsupported file type
/Users/carson.katri/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf: warning: '/Users/carson.katri/Documents/lightpanda/browser/zig-out/lib/liblightpanda.a': /Users/carson.katri/Documents/lightpanda/browser/vendor/netsurf/out/android-aarch64/lib/libparserutils.a has an unsupported file type
/Users/carson.katri/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf: warning: '/Users/carson.katri/Documents/lightpanda/browser/zig-out/lib/liblightpanda.a': /Users/carson.katri/Documents/lightpanda/browser/vendor/netsurf/out/android-aarch64/lib/libwapcaplet.a has an unsupported file type
/Users/carson.katri/android-ndk/android-ndk-r27d/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf: warning: '/Users/carson.katri/Documents/lightpanda/browser/zig-out/lib/liblightpanda.a': /Users/carson.katri/Documents/lightpanda/browser/v8/out/android/release/obj/zig/libc_v8.a has an unsupported file type