#/bin/zsh

brew install pkg-config

make install

mkdir -p v8/out/debug/obj/zig
# curl -L -o v8/out/debug/obj/zig/libc_v8.a https://github.com/lightpanda-io/zig-v8-fork/releases/download/v0.1.28/libc_v8_13.6.233.8_macos_aarch64.a
cp ../zig-v8-fork/libc_v8.a v8/out/debug/obj/zig/libc_v8.a

zig build