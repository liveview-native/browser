#/bin/zsh

rm -rf lightpanda.xcframework

zig build -Dtarget=aarch64-ios-simulator -Dcpu=apple_m1 --release=safe

xcodebuild -create-xcframework -library zig-out/lib/liblvn.a -headers include -output lightpanda.xcframework
