const std = @import("std");

pub fn processMessage(cmd: anytype) !void {
    try sendInspector(cmd);
}

fn sendInspector(cmd: anytype) !void {
    const bc = cmd.browser_context orelse return error.BrowserContextNotLoaded;

    // the result to return is handled directly by the inspector.
    bc.callInspector(cmd.input.json);
}