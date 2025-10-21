const std = @import("std");

pub fn processMessage(cmd: anytype) !void {
    try sendInspector(cmd);
}

fn sendInspector(cmd: anytype) !void {
    if (cmd.input.session_id == null) {
        return cmd.sendResult(null, .{});
    }

    const bc = cmd.browser_context orelse return error.BrowserContextNotLoaded;

    // the result to return is handled directly by the inspector.
    bc.callInspector(cmd.input.json);
}