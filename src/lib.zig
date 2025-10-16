const std = @import("std");
const App = @import("app.zig").App;
const Browser = @import("browser/browser.zig").Browser;
const Session = @import("browser/session.zig").Session;
const Page = @import("browser/page.zig").Page;
const Scheduler = @import("browser/Scheduler.zig");
const CDPT = @import("cdp/cdp.zig").CDPT;
const BrowserContext = @import("cdp/cdp.zig").BrowserContext;
const accept_extension = @import("lvn/accept_extension.zig");

export fn lightpanda_app_init() ?*anyopaque {
    @import("log.zig").opts.level = .warn;
    const allocator = std.heap.c_allocator;

    @import("log.zig").opts.level = .warn;

    const app = App.init(allocator, .{
        // .run_mode = .serve,
        // .tls_verify_host = false
        .run_mode = .serve,
        .tls_verify_host = false,
        .user_agent = "Lightpanda",
        // .http_proxy = null,
        // .proxy_bearer_token = args.proxyBearerToken(),
        // .tls_verify_host = args.tlsVerifyHost(),
        // .http_timeout_ms = args.httpTimeout(),
        // .http_connect_timeout_ms = args.httpConnectTiemout(),
        // .http_max_host_open = args.httpMaxHostOpen(),
        // .http_max_concurrent = args.httpMaxConcurrent(),
    }) catch return null;

    return app;
}

export fn lightpanda_app_deinit(app_ptr: *anyopaque) void {
    const app: *App = @ptrCast(@alignCast(app_ptr));
    app.deinit();
}

export fn lightpanda_browser_init(app_ptr: *anyopaque) ?*anyopaque {
    const app: *App = @ptrCast(@alignCast(app_ptr));

    const browser = app.allocator.create(Browser) catch return null;
    browser.* = Browser.init(app) catch return null;

    return browser;
}

export fn lightpanda_browser_deinit(browser_ptr: *anyopaque) void {
    const browser: *Browser = @ptrCast(@alignCast(browser_ptr));
    browser.deinit();
}

export fn lightpanda_browser_new_session(browser_ptr: *anyopaque) ?*anyopaque {
    const browser: *Browser = @ptrCast(@alignCast(browser_ptr));
    const session = browser.newSession() catch return null;
    return session;
}

export fn lightpanda_session_create_page(session_ptr: *anyopaque) ?*anyopaque {
    const session: *Session = @ptrCast(@alignCast(session_ptr));
    const page = session.createPage() catch return null;
    page.auto_enable_dom_monitoring = true;
    return page;
}

export fn lightpanda_session_page(session_ptr: *anyopaque) ?*anyopaque {
    const session: *Session = @ptrCast(@alignCast(session_ptr));
    return &session.page;
}

export fn lightpanda_page_navigate(page_ptr: *anyopaque, url: [*:0]const u8) void {
    const page: *Page = @ptrCast(@alignCast(page_ptr));
    page.navigate(std.mem.span(url), .{}) catch return;
}

const NativeClientHandler = *const fn (ctx: *anyopaque, message: [*:0]const u8) callconv(.c) void;
const NativeClientFocusedNodeHandler = *const fn (ctx: *anyopaque, node_id: c_int) callconv(.c) void;

const NativeClient = struct {
    allocator: std.mem.Allocator,
    send_arena: std.heap.ArenaAllocator,
    // sent: std.ArrayListUnmanaged(std.json.Value) = .{},
    // serialized: std.ArrayListUnmanaged([]const u8) = .{},
    handler: NativeClientHandler,
    focused_node_handler: NativeClientFocusedNodeHandler,
    ctx: *anyopaque,

    // devtools server
    listener: ?std.net.Server = null,
    devtools: ?DevTools = null,
    recv_buffer: [512 * 1024 + 14 + 140]u8 = undefined,
    send_buffer: [512 * 1024 + 14 + 140]u8 = undefined,
    conn_reader: ?std.net.Stream.Reader = null,
    conn_writer: ?std.net.Stream.Writer = null,

    const DevTools = struct {
        socket: std.http.Server.WebSocket,
        allocator: std.mem.Allocator,

        pub fn sendJSON(self: *DevTools, message: anytype) !void {
            const msg = try std.json.Stringify.valueAlloc(self.allocator, message, .{});
            std.log.info("devtools sending -- {s}", .{msg});
            try self.socket.writeMessage(msg, .text);
        }
    };

    fn init(alloc: std.mem.Allocator, handler: NativeClientHandler, focused_node_handler: NativeClientFocusedNodeHandler, ctx: *anyopaque) NativeClient {
        return .{ .allocator = alloc, .send_arena = std.heap.ArenaAllocator.init(alloc), .handler = handler, .focused_node_handler = focused_node_handler, .ctx = ctx };
    }

    pub fn sendJSON(self: *NativeClient, message: anytype, opts: std.json.Stringify.Options) !void {
        var opts_copy = opts;
        opts_copy.whitespace = .minified;
        const serialized = try std.json.Stringify.valueAlloc(self.allocator, message, opts_copy);

        const slice = try self.allocator.dupeZ(u8, serialized);
        defer self.allocator.free(slice);
        self.handler(self.ctx, slice.ptr);

        if (self.devtools) |*devtools| { // forward events to devtools
            if (std.mem.startsWith(u8, slice, "{\"method\":")) {
                try devtools.sendJSON(message);
            }
        }
    }

    pub fn sendJSONRaw(self: *NativeClient, buf: std.ArrayListUnmanaged(u8)) !void {
        const msg = buf.items[10..]; // CDP adds 10 0s for a WebSocket header.
        const slice = try self.allocator.dupeZ(u8, msg);
        defer self.allocator.free(slice);
        self.handler(self.ctx, slice.ptr);

        // raw messages are from the v8 inspector.
        // CDP always sends this to the client, not the target.
        // So this message might be for the client, or for the devtools.
        // Forward it to the devtools to be safe.
        if (self.devtools) |*devtools| {
            std.log.info("devtools sending raw -- {s}", .{msg});
            try devtools.socket.writeMessage(msg, .text);
        }
    }

    pub fn setFocusedNode(self: *NativeClient, node_id: ?u32) void {
        if (node_id) |id| {
            self.focused_node_handler(self.ctx, @intCast(id));
        }
    }
};

const CDP = CDPT(struct {
    pub const Client = *NativeClient;
});

export fn lightpanda_cdp_init(app_ptr: *anyopaque, handler: NativeClientHandler, focused_node_handler: NativeClientFocusedNodeHandler, ctx: *anyopaque) ?*anyopaque {
    const app: *App = @ptrCast(@alignCast(app_ptr));

    const client = app.allocator.create(NativeClient) catch return null;
    client.* = NativeClient.init(app.allocator, handler, focused_node_handler, ctx);

    const cdp = app.allocator.create(CDP) catch return null;
    cdp.* = CDP.init(app, client) catch return null;

    return cdp;
}

export fn lightpanda_cdp_deinit(cdp_ptr: *anyopaque) void {
    const cdp: *CDP = @ptrCast(@alignCast(cdp_ptr));
    cdp.deinit();
}

export fn lightpanda_cdp_create_browser_context(cdp_ptr: *anyopaque) ?[*:0]const u8 {
    const cdp: *CDP = @ptrCast(@alignCast(cdp_ptr));
    const id = cdp.createBrowserContext() catch return null;

    const page = cdp.browser_context.?.session.createPage() catch return null;
    page.auto_enable_dom_monitoring = true;

    const target_id = cdp.target_id_gen.next();
    cdp.browser_context.?.target_id = target_id;

    const session_id = cdp.session_id_gen.next();
    cdp.browser_context.?.extra_headers.clearRetainingCapacity();
    cdp.browser_context.?.session_id = session_id;

    const slice = cdp.allocator.dupeZ(u8, id) catch return null;
    return slice.ptr;
}

export fn lightpanda_cdp_browser(cdp_ptr: *anyopaque) ?*anyopaque {
    const cdp: *CDP = @ptrCast(@alignCast(cdp_ptr));
    return &cdp.browser;
}

export fn lightpanda_cdp_process_message(cdp_ptr: *anyopaque, msg: [*:0]const u8) void {
    const cdp: *CDP = @ptrCast(@alignCast(cdp_ptr));
    cdp.processMessage(std.mem.span(msg)) catch return;
}

export fn lightpanda_cdp_browser_context(cdp_ptr: *anyopaque) *anyopaque {
    const cdp: *CDP = @ptrCast(@alignCast(cdp_ptr));
    return &cdp.browser_context.?;
}

// returns -1 if no session/page, or if no events reamin, otherwise returns
// milliseconds until next scheduled task
export fn lightpanda_cdp_page_wait(cdp_ptr: *anyopaque, ms: i32) c_int {
    const cdp: *CDP = @ptrCast(@alignCast(cdp_ptr));
    _ = cdp.pageWait(ms);

    // it's okay to panic if the session or page don't exist.
    const scheduler = &cdp.browser.session.?.page.?.scheduler;
    const delay = cdp_peek_next_delay_ms(scheduler) orelse -1;

    const client: *NativeClient = cdp.client;

    if (client.devtools) |*devtools| {
        // const aux_data = std.fmt.allocPrint(cdp.allocator, "{{\"isDefault\":true,\"type\":\"default\",\"frameId\":\"{s}\"}}", .{
        //     cdp.browser_context.?.target_id.?
        // }) catch return delay;
        // cdp.browser_context.?.inspector.contextCreated(
        //     cdp.browser_context.?.session.page.?.js,
        //     "",
        //     cdp.browser_context.?.session.page.?.origin(cdp.allocator) catch return delay,
        //     aux_data,
        //     true
        // );

        const message = devtools.socket.readSmallMessage() catch return delay;
        switch (message.opcode) {
            .text => {
                const arena = &cdp.message_arena;
                defer _ = arena.reset(.{ .retain_with_limit = 1024 * 16 });
                cdp.dispatch(arena.allocator(), devtools, message.data) catch return delay;
                if (std.mem.endsWith(u8, message.data, "\"method\":\"Target.setAutoAttach\",\"params\":{\"autoAttach\":true,\"waitForDebuggerOnStart\":true,\"flatten\":true}}")) {
                    devtools.sendJSON(.{
                        .method = "Target.attachedToTarget",
                        .params = .{
                            .sessionId = cdp.browser_context.?.session_id.?,
                            .targetInfo = .{
                                .targetId = cdp.browser_context.?.target_id.?,
                                .type = "page",
                                .title = "Title",
                                .url = cdp.browser_context.?.session.page.?.url.raw,
                                .attached = true,
                                .canAccessOpener = true,
                                .browserContextId = cdp.browser_context.?.id,
                            },
                            .waitForDebugger = false,
                        }
                    }) catch return delay;
                    devtools.sendJSON(.{
                        .method = "Runtime.executionContextCreated",
                        .params = .{
                            .context = .{
                                .id = cdp.browser_context.?.session.page.?.js.v8_context.debugContextId(),
                                .origin = cdp.browser_context.?.session.page.?.origin(cdp.allocator) catch return delay,
                                .name = "",
                                // .uniqueId = <we can't get the unique ID from v8 yet, but this is experimental anyways>
                                .auxData = .{
                                    .isDefault = true,
                                    .type = "default",
                                    .frameId = cdp.browser_context.?.target_id.?
                                }
                            }
                        },
                        .sessionId = cdp.browser_context.?.session_id.?
                    }) catch return delay;
                }
            },
            else => return delay,
        }
        std.log.info("{} -- {s}", .{message.opcode, message.data});
        
        // devtools.socket.input.rebase(1024) catch return delay;
        
        // devtools.socket.input.buffer = undefined;
        // devtools.socket.input.seek = 0;
        // devtools.socket.input.end = 0;

        // if (devtools.socket.input.peek(1)) |peek| {
        //     if (peek.len > 0) {
        //     }
        // } else |err| {
        //     std.log.err("peek error: {}", .{err});
        //     return delay;
        // }
    } else if (client.listener) |*listener| {
        // if we get a basic http request, respond to it in this run loop.
        const conn = listener.accept() catch return delay;
        client.conn_reader = conn.stream.reader(&client.recv_buffer);
        client.conn_writer = conn.stream.writer(&client.send_buffer);
        var server = std.http.Server.init(client.conn_reader.?.interface(), &client.conn_writer.?.interface);
        
        var req = server.receiveHead() catch return delay;

        std.log.info("{s}", .{req.head.target});

        if (std.mem.eql(u8, req.head.target, "/json/version")) {
            var writer = std.io.Writer.Allocating.init(client.allocator);
            defer writer.deinit();

            var stringify = std.json.Stringify{ .writer = &writer.writer };

            stringify.beginObject() catch return delay;
            stringify.objectField("Browser") catch return delay;
            stringify.write("Chrome/72.0.3601.0") catch return delay;
            stringify.objectField("Protocol-Version") catch return delay;
            stringify.write("1.3") catch return delay;
            stringify.objectField("User-Agent") catch return delay;
            stringify.write("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3601.0 Safari/537.36") catch return delay;
            stringify.objectField("V8-Version") catch return delay;
            stringify.write("7.2.233") catch return delay;
            stringify.objectField("WebKit-Version") catch return delay;
            stringify.write("537.36 (@cfede9db1d154de0468cb0538479f34c0755a0f4)") catch return delay;
            stringify.objectField("webSocketDebuggerUrl") catch return delay;
            stringify.write("ws://localhost:9222/devtools/browser/0") catch return delay;
            stringify.endObject() catch return delay;

            const json = writer.toOwnedSlice() catch return delay;

            req.respond(json, .{}) catch return delay;
            return delay;
        }

        if (std.mem.startsWith(u8, req.head.target, "/json/list")) {
            const list = std.json.Stringify.valueAlloc(client.allocator, .{
                .{
                    .description = "",
                    .devtoolsFrontendUrl = "/devtools/inspector.html?ws=localhost:9222/devtools/page/0",
                    .id = "0",
                    .title = "Page",
                    .type = "page",
                    .url = cdp.browser.session.?.page.?.url.raw,
                    .webSocketDebuggerUrl = "ws://localhost:9222/devtools/page/0"
                }
            }, .{}) catch return delay;
            req.respond(list, .{}) catch return delay;
            return delay;
        }

        // open websocket connection
        if (std.mem.eql(u8, req.head.target, "/devtools/page/0")) {
            switch (req.upgradeRequested()) {
                .websocket => |key| {
                    std.log.info("connecting websocket for page 0 with key {s}", .{ key orelse "" });
                    client.devtools = NativeClient.DevTools{
                        .socket = req.respondWebSocket(.{.key = key orelse ""}) catch return delay,
                        .allocator = client.allocator,
                    };
                    client.devtools.?.socket.flush() catch return delay;

                    return delay;
                },
                else => return delay,
            }
        }
    }

    return delay;
}

fn cdp_peek_next_delay_ms(scheduler: *Scheduler) ?i32 {
    var queue = queue: {
        if (scheduler.high_priority.count() == 0) {
            if (scheduler.low_priority.count() == 0) return null;
            break :queue scheduler.low_priority;
        } else {
            break :queue scheduler.high_priority;
        }
    };

    const now = std.time.milliTimestamp();
    // we know this must exist because the count was not 0.
    const next_task = queue.peek().?;

    const time_to_next = next_task.ms - now;
    return if (time_to_next > 0) @intCast(time_to_next) else 0;
}

export fn lightpanda_browser_context_session(browser_context_ptr: *anyopaque) *anyopaque {
    const browser_context: *BrowserContext(CDP) = @ptrCast(@alignCast(browser_context_ptr));
    return browser_context.session;
}

export fn lightpanda_devtools_init(cdp_ptr: *anyopaque) void {
    const cdp: *CDP = @ptrCast(@alignCast(cdp_ptr));

    const client: *NativeClient = cdp.client;

    const address = std.net.Address.parseIp4("127.0.0.1", 9222) catch return;
    client.listener = address.listen(.{ .force_nonblocking = true, .reuse_address = true }) catch return;
}

// const DevToolsServer = @import("devtools.zig").Server;

// export fn lightpanda_devtools_init(cdp_ptr: *anyopaque) ?*anyopaque {
//     const cdp: *CDP = @ptrCast(@alignCast(cdr));

//     const address = std.net.Address.parseIp("127.0.0.1", 9583) catch return null;
//     const devtools_server = cdp.browser.app.allocator.create(DevToolsServer) catch return null;
//     devtools_server.* = DevToolsServer.init(&cdp.browser, address) catch return null;

//     return devtools_server;
// }

// export fn lightpanda_devtools_run(devtools_ptr: *anyopaque) void {
//     const address = std.net.Address.parseIp("127.0.0.1", 9583) catch return;
//     const devtools: *DevToolsServer = @ptrCast(@alignCast(devtools_ptr));
//     devtools.run(address, 1000) catch return;
// }

// export fn lightpanda_devtools_read_loop(devtools_ptr: *anyopaque) void {
//     const devtools: *DevToolsServer = @ptrCast(@alignCast(devtools_ptr));

//     if (devtools.cdp_client) |cdp_client| {
//         if (try cdp_client.readSocket() == false) {
//             return;
//         }
//     }
// }

// export fn lightpanda_devtools_deinit(devtools_ptr: *anyopaque) void {
//     const devtools: *DevToolsServer = @ptrCast(@alignCast(devtools_ptr));
//     devtools.deinit();
// }
export const set_lvn_accept = accept_extension.set_lvn_accept;
