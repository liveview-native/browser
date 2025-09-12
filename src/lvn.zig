const std = @import("std");
const Browser = @import("browser/browser.zig").Browser;
const Page = @import("browser/page.zig").Page;
const App = @import("app.zig").App;
const log = @import("log.zig");

export fn lvn_init(input_url: [*:0]u8) ?*anyopaque {
    const alloc = std.heap.c_allocator;

    // _app is global to handle graceful shutdown.
    const app = App.init(alloc, .{ .run_mode = .fetch, .tls_verify_host = false }) catch return null;

    const url = std.mem.span(input_url);

    // browser
    const browser = alloc.create(Browser) catch return null;
    browser.* = Browser.init(app) catch return null;

    var session = browser.newSession() catch return null;

    // page
    const page = session.createPage() catch return null;

    _ = page.navigate(url, .{}) catch |err| switch (err) {
        error.UnsupportedUriScheme, error.UriMissingHost => {
            log.fatal(.app, "invalid fetch URL", .{ .err = err, .url = url });
            return null;
        },
        else => {
            log.fatal(.app, "fetch error", .{ .err = err, .url = url });
            return null;
        },
    };

    _ = session.wait(5);

    return browser;
}

export fn lvn_dump_page(lvn: ?*anyopaque) void {
    const browser: *Browser = @ptrCast(@alignCast(lvn.?));
    const page: *Page = &browser.session.?.page.?;

    scheduleOnEventLoop(page, dumpPage, {}) catch return;
}

fn dumpPage(page: *Page, _: void) void {
    // dump
    var writer = std.fs.File.stdout().writer(&.{});
    page.dump(.{
        .page = page,
    }, &writer.interface) catch return;
    writer.interface.flush() catch return;
}

export fn lvn_dispatch_eventloop(lvn: ?*anyopaque) void {
    const browser: *Browser = @ptrCast(@alignCast(lvn.?));
    // eagerly jump through the javascript event loop, clearing events on the stack.
    _ = browser.session.?.page.?.wait(0);
}

export fn lvn_deinit(lvn: ?*anyopaque) void {
    const browser: *Browser = @ptrCast(@alignCast(lvn.?));
    const app = browser.app;
    browser.deinit();
    app.deinit();
}

pub fn Arg(F: type) type {
    return @typeInfo(F).@"fn".params[1].type.?;
}

pub fn Return(F: type) type {
    return @typeInfo(F).@"fn".return_type.?;
}

/// func must be a 2-arity function which takes *Page as its first parameter.
/// func should have a void return.
/// second parameter may be anything and scheduleOnEventLoop performs a typesafe specialization
/// over whatever payload you would like to use.
fn scheduleOnEventLoop(page: *Page, func: anytype, arg: Arg(@TypeOf(func))) !void {
    const A = Arg(@TypeOf(func));
    const R = Return(@TypeOf(func));

    const OpContext = struct { page: *Page, arg: A, ret: R };

    const Wrapped = struct {
        fn operation(ctx_ptr: *anyopaque) ?u32 {
            const ctx: *OpContext = @ptrCast(@alignCast(ctx_ptr));
            defer ctx.page.arena.destroy(ctx);
            @call(.auto, func, .{ ctx.page, ctx.arg });
            // retval is "repeat delay."  Do NOT return zero.
            return null;
        }
    };

    const ctx = try page.arena.create(OpContext);
    errdefer page.arena.destroy(ctx);

    // assemble the Operation Context
    ctx.* = .{ .page = page, .arg = arg, .ret = undefined };

    try page.scheduler.add(ctx, Wrapped.operation, 0, .{ .name = @typeName(@TypeOf(func)) });
}
