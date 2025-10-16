//! accept_extension.
//!
//! allows for the definition of specifications to be added (swift-side) to the accept header
//!
//! see: https://gist.github.com/bcardarella/dbc09038f4e07fe2056743fda28502dd
//!
//! To use from swift:
//!
//! import Foundation
//!
//! let accept: [String: Any] = [
//!   "target": "ios",
//!   "version": "18.0",
//!   "locale": "en-US",
//!   "device": [
//!     "model": "iPhone15,2",
//!     "screen": [
//!         "width": "1179",
//!         "height": "2556",
//!         "scale": "3"
//!     ]
//!   ]
//! ]
//!
//! func example() {
//!    err = set_lvn_accept(accept as CFDictionary)
//!    _ = err; // consider testing error here.
//! }

const std = @import("std");
const cf = @cImport(@cInclude("CoreFoundation/CoreFoundation.h"));

const AppendError = error{ badtype, OutOfMemory, string_error, bad_char, missing_required };

// default the value to target=ios;
const default_value: []const u8 = "; target=ios";
pub var value: []const u8 = default_value;

const allocator = std.heap.c_allocator;

fn append_dict_value(dict: cf.CFDictionaryRef, prefix: []u8, comptime root: bool) AppendError!void {
    const n: cf.CFIndex = cf.CFDictionaryGetCount(dict);
    const keys = try allocator.alloc(?*const anyopaque, @intCast(n));
    const values = try allocator.alloc(?*const anyopaque, @intCast(n));

    cf.CFDictionaryGetKeysAndValues(dict, keys.ptr, values.ptr);

    for (keys, values) |key_op, value_op| {
        if (cf.CFGetTypeID(key_op) != cf.CFStringGetTypeID()) return error.badtype;

        const newprefix = try setprefix(prefix, @ptrCast(key_op), root);
        defer allocator.free(newprefix);

        const vt: cf.CFTypeID = cf.CFGetTypeID(value_op);

        if (vt == cf.CFStringGetTypeID()) {
            try append_string_value(@ptrCast(value_op), newprefix);
            continue;
        }
        if (vt == cf.CFDictionaryGetTypeID()) {
            try append_dict_value(@ptrCast(value_op), newprefix, false);
            continue;
        }
        return error.badtype;
    }
}

fn append_string_value(string_cf: cf.CFStringRef, prefix: []u8) !void {
    const old_value = value;

    const string_len: usize = @intCast(cf.CFStringGetLength(string_cf));

    const append_len = prefix.len + 3 + string_len;

    const index = if (value.ptr == default_value.ptr) idx: {
        value = try allocator.alloc(u8, append_len);
        break :idx 0;
    } else idx: {
        value = try allocator.realloc(@constCast(value), old_value.len + append_len);
        break :idx old_value.len;
    };

    {
        const set_value = @constCast(value);
        @memmove(set_value[index .. index + 2], "; ");
        @memmove(set_value[index + 2 .. index + prefix.len + 2], prefix);
        set_value[index + prefix.len + 2] = '=';
        try fill_from_cf_str(set_value[index + prefix.len + 3 ..], string_cf);
    }
}

const default_prefix: []u8 = "";

fn setprefix(prefix: []u8, suffix_cf: cf.CFStringRef, comptime root: bool) ![]u8 {
    const suffix_len: usize = @intCast(cf.CFStringGetLength(suffix_cf));
    var result: []u8 = undefined;
    if (root) {
        result = try allocator.alloc(u8, suffix_len);
        try fill_from_cf_str(result, suffix_cf);
    } else {
        result = try allocator.alloc(u8, prefix.len + 1 + suffix_len);
        @memmove(result[0..prefix.len], prefix);
        result[prefix.len] = '.';
        try fill_from_cf_str(result[prefix.len + 1 ..], suffix_cf);
    }

    return result;
}

fn fill_from_cf_str(dest: []u8, cf_str: cf.CFStringRef) !void {
    var copied: c_long = undefined;
    const success = cf.CFStringGetBytes(
        cf_str, 
        cf.CFRangeMake(0, @intCast(dest.len)), 
        cf.kCFStringEncodingASCII, 
        0, 
        0, 
        dest.ptr, 
        @intCast(dest.len), 
        &copied);

    for (dest) |char| {
        if (char == 0) return error.bad_char; 
    }
    if (success == 0) return error.string_error;
    if (copied != dest.len) unreachable;
}

pub fn set_lvn_accept(accept: cf.CFDictionaryRef) callconv(.c) c_int {
    append_dict_value(accept orelse return 1, default_prefix, true) catch |err| switch (err) {
        error.badtype => return 1,
        error.OutOfMemory => return 2,
        error.bad_char => return 3,
        error.string_error => return 4,
        error.missing_required => return 5
    };
    return 0;
}

const lvn_accept_prefix = "accept: application/swiftui+vml";

pub fn get_lvn_accept_header() ![:0]u8 {
    // this function leaks.  Consider it okay.
    const full_len = lvn_accept_prefix.len + value.len;
    const accept = try allocator.allocSentinel(u8, full_len, 0);
    @memmove(accept[0..lvn_accept_prefix.len], lvn_accept_prefix);
    @memmove(accept[lvn_accept_prefix.len..], value);
    return accept;
}
