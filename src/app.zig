const std = @import("std");

const Allocator = std.mem.Allocator;

const log = @import("log.zig");
const Http = @import("http/Http.zig");
const Platform = @import("runtime/js.zig").Platform;

const Telemetry = @import("telemetry/telemetry.zig").Telemetry;
const Notification = @import("notification.zig").Notification;

// Container for global state / objects that various parts of the system
// might need.
pub const App = struct {
    http: Http,
    config: Config,
    platform: Platform,
    allocator: Allocator,
    telemetry: Telemetry,
    app_dir_path: ?[]const u8,
    notification: *Notification,

    pub const RunMode = enum {
        help,
        fetch,
        serve,
        version,
    };

    pub const Config = struct {
        run_mode: RunMode,
        tls_verify_host: bool = true,
        http_proxy: ?[:0]const u8 = null,
        proxy_bearer_token: ?[:0]const u8 = null,
        http_timeout_ms: ?u31 = null,
        http_connect_timeout_ms: ?u31 = null,
        http_max_host_open: ?u8 = null,
        http_max_concurrent: ?u8 = null,
    };

    pub fn init(allocator: Allocator, config: Config) !*App {
        const app = try allocator.create(App);
        errdefer allocator.destroy(app);

        const notification = try Notification.init(allocator, null);
        errdefer notification.deinit();

        var http = try Http.init(allocator, .{
            .max_host_open = config.http_max_host_open orelse 4,
            .max_concurrent = config.http_max_concurrent orelse 10,
            .timeout_ms = config.http_timeout_ms orelse 5000,
            .connect_timeout_ms = config.http_connect_timeout_ms orelse 0,
            .http_proxy = config.http_proxy,
            .tls_verify_host = config.tls_verify_host,
            .proxy_bearer_token = config.proxy_bearer_token,
        });
        errdefer http.deinit();

        const platform = try Platform.init();
        errdefer platform.deinit();

        const app_dir_path = getAndMakeAppDir(allocator);

        app.* = .{
            .http = http,
            .allocator = allocator,
            .telemetry = undefined,
            .platform = platform,
            .app_dir_path = app_dir_path,
            .notification = notification,
            .config = config,
        };

        app.telemetry = try Telemetry.init(app, config.run_mode);
        errdefer app.telemetry.deinit();

        try app.telemetry.register(app.notification);

        return app;
    }

    pub fn deinit(self: *App) void {
        const allocator = self.allocator;
        if (self.app_dir_path) |app_dir_path| {
            allocator.free(app_dir_path);
        }
        self.telemetry.deinit();
        self.notification.deinit();
        self.http.deinit();
        self.platform.deinit();
        allocator.destroy(self);
    }
};

fn getAndMakeAppDir(allocator: Allocator) ?[]const u8 {
    if (@import("builtin").is_test) {
        return allocator.dupe(u8, "/tmp") catch unreachable;
    }
    // const app_dir_path = std.fs.getAppDataDir(allocator, "lightpanda") catch |err| {
    //     log.warn(.app, "get data dir", .{ .err = err });
    //     return null;
    // };
    const home_dir = std.posix.getenv("HOME") orelse {
        // log.warn(.app, "get data dir", .{});
        return null;
    };
    const app_dir_path = std.fs.path.join(allocator, &[_][]const u8{ home_dir, "Library", "Application Support", "" }) catch return null;

    std.fs.cwd().makePath(app_dir_path) catch |err| switch (err) {
        error.PathAlreadyExists => return app_dir_path,
        else => {
            allocator.free(app_dir_path);
            log.warn(.app, "create data dir", .{ .err = err, .path = app_dir_path });
            return null;
        },
    };
    return app_dir_path;
}

const Browser = @import("browser/browser.zig").Browser;

export fn lightpanda_app_init(input_url: [*:0]u8) usize {
    const alloc = std.heap.c_allocator;

    // _app is global to handle graceful shutdown.
    const app = App.init(alloc, .{ .run_mode = .fetch, .tls_verify_host = false }) catch return 2;

    const url = std.mem.span(input_url);

    // browser
    const browser = alloc.create(Browser) catch return 0;
    browser.* = Browser.init(app) catch return 0;

    var session = browser.newSession() catch return 0;

    // page
    const page = session.createPage() catch return 0;

    _ = page.navigate(url, .{}) catch |err| switch (err) {
        error.UnsupportedUriScheme, error.UriMissingHost => {
            log.fatal(.app, "invalid fetch URL", .{ .err = err, .url = url });
            return 0;
        },
        else => {
            log.fatal(.app, "fetch error", .{ .err = err, .url = url });
            return 0;
        },
    };

    session.wait(5); // 5 seconds

    // dump
    var stdout = std.fs.File.stdout();
    var writer = stdout.writer(&.{});
    page.dump(.{
        .page = page,
    }, &writer.interface) catch return 0;
    writer.interface.flush() catch return 0;

    return @intFromPtr(browser);
}

export fn lightpanda_app_deinit(address: usize) void {
    const browser = @as(?*Browser, @ptrFromInt(address)).?;
    const app = browser.app;
    browser.deinit();
    app.deinit();
}
