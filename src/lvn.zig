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

    return browser;
}

export fn lvn_dump(lvn: ?*anyopaque) void {
    const browser: *Browser = @alignCast(@ptrCast(lvn.?));
    const page: *Page = &browser.session.?.page.?;
    page.domOperation(dump_page, {}) catch return;
}

fn dump_page(page: *Page, _: void) void {
    var stdout = std.fs.File.stdout();
    var writer = stdout.writer(&.{});
    page.dump(.{
        .page = page,
    }, &writer.interface) catch return;
    writer.interface.flush() catch return;
}

export fn lvn_deinit(lvn: ?*anyopaque) void {
    const browser: *Browser = @alignCast(@ptrCast(lvn.?));
    const app = browser.app;
    browser.deinit();
    app.deinit();
}
