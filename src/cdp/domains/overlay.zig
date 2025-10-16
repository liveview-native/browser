const std = @import("std");
const Node = @import("../Node.zig");

pub fn processMessage(cmd: anytype) !void {
    const action = std.meta.stringToEnum(enum {
        enable,
        hideHighlight,
        highlightNode
    }, cmd.input.action) orelse return error.UnknownMethod;

    switch (action) {
        .enable => return cmd.sendResult(null, .{}),
        .hideHighlight => return hideHighlight(cmd),
        .highlightNode => return highlightNode(cmd),
    }
}

fn hideHighlight(cmd: anytype) !void {
    cmd.cdp.setHighlightedNode(null);
    
    return cmd.sendResult(null, .{});
}

fn highlightNode(cmd: anytype) !void {
    const params = (try cmd.params(struct {
        nodeId: ?Node.Id = null,
    })) orelse return error.InvalidParams;

    cmd.cdp.setHighlightedNode(params.nodeId);

    return cmd.sendResult(null, .{});
}