#!/bin/zsh

set -e

SDK=$(xcrun --sdk iphonesimulator --show-sdk-path) zig build -Dtarget=aarch64-ios-simulator -Dcpu=apple_m1 --release=safe -freference-trace=13
zig build

rm -rf lightpanda.xcframework

xcodebuild -create-xcframework -library zig-out/lib/aarch64-macos.15.6.1...15.6.1-none/liblightpanda.a -headers include \
    -library zig-out/lib/aarch64-ios.15.0...18.6-simulator/liblightpanda.a -headers include \
    -output lightpanda.xcframework