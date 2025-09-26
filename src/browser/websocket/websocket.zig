// Copyright (C) 2023-2024  Lightpanda (Selecy SAS)
//
// Francis Bouvier <francis@lightpanda.io>
// Pierre Tachoire <pierre@lightpanda.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");

const Env = @import("../env.zig").Env;
const Function = Env.Function;
const JsObject = Env.JsObject;
const EventTarget = @import("../dom/event_target.zig").EventTarget;
const EventHandler = @import("../events/event.zig").EventHandler;
const parser = @import("../netsurf.zig");
const Page = @import("../page.zig").Page;
const Http = @import("../../http/Http.zig");
const log = @import("../../log.zig");
const c = Http.c;

pub const WebSocket = struct {
    pub const prototype = *EventTarget;

    // WebSocket connection state constants
    pub const CONNECTING: u16 = 0;
    pub const OPEN: u16 = 1;
    pub const CLOSING: u16 = 2;
    pub const CLOSED: u16 = 3;

    // Extend libdom event target for pure zig struct.
    base: parser.EventTargetTBase = parser.EventTargetTBase{ .internal_target_type = .websocket },

    // WebSocket properties
    uri: std.Uri,
    uri_str: []const u8 = "",
    protocols: []const []const u8 = &.{},
    ready_state: u16 = CONNECTING,
    buffered_amount: u32 = 0,
    extensions: []const u8 = "",
    protocol: []const u8 = "",
    binary_type: []const u8 = "blob", // "blob" or "arraybuffer"

    // Internal connection state
    curl_handle: ?*c.CURL = null,
    page: ?*Page = null,
    allocator: std.mem.Allocator = undefined,

    // Event handlers
    onopen_cbk: ?Function = null,
    onerror_cbk: ?Function = null,
    onclose_cbk: ?Function = null,
    onmessage_cbk: ?Function = null,

    pub fn constructor(uri_str: []const u8, protocols: ?[]const []const u8, page: *Page) !*WebSocket {
        // Validate URL format
        const uri = try std.Uri.parse(uri_str);

        // Check if it's a valid WebSocket URL
        if (!std.mem.eql(u8, uri.scheme, "ws") and !std.mem.eql(u8, uri.scheme, "wss")) {
            return error.InvalidURL;
        }

        // Allocate WebSocket on heap for stable address
        const websocket = try page.arena.create(WebSocket);
        websocket.* = WebSocket{
            .uri = uri,
            .uri_str = uri_str,
            .protocols = if (protocols) |p| try page.arena.dupe([]const u8, p) else &.{},
            .ready_state = CONNECTING,
            .page = page,
            .allocator = page.arena,
        };

        // Initialize libcurl handle but don't connect yet

        websocket.initHandle() catch |err| {
            log.err(.ws, "ws initHandle failed", .{ .err = err });
            return err;
        };

        log.info(.ws, "ws handle initialized", .{});

        // Schedule asynchronous connection attempt
        page.scheduler.add(websocket, connectionTask, 0, .{ .name = "WebSocket connection" }) catch |err| {
            log.err(.ws, "ws reschedule failed", .{ .err = err });
        };

        log.info(.ws, "ws connection scheduled", .{});
        return websocket;
    }

    const CurlFail = struct {
        error_code: c_uint,
        op: Operation,
        const Operation = enum {uri, connect_only, ws_options, verify_host, verify_peer, cookie, connect};
        fn do_log(fail: @This()) void {
            log.err(.ws, "ws curl set option failed", .{ .curl_code = fail.error_code, .operation = fail.op });
        }
    };

    fn set_fail(curl_result: c_uint, failure: *?CurlFail, op: CurlFail.Operation) !void {
        if (curl_result != 0) {
            failure.* = .{
                .error_code = curl_result,
                .op = op,
            };
            return error.curl_failure;
        }
    }

    fn initHandle(self: *WebSocket) !void {
        // if the page or uri don't exist we shouldn't be attempting to initialize the handle.
        const page = self.page orelse return error.InvalidState;

        // Create curl handle
        self.curl_handle = c.curl_easy_init();
        if (self.curl_handle == null) {
            log.err(.ws, "ws curl_easy_init failed", .{});
            return error.CurlInitFailed;
        }
        log.info(.ws, "ws curl handle created", .{});

        var curl_fail: ?CurlFail = null;

        errdefer {
            if (self.curl_handle) |handle| {
                c.curl_easy_cleanup(handle);
                self.curl_handle = null;
            }

            if (curl_fail) |fail| fail.do_log();
        }

        const handle = self.curl_handle.?;
        // Set URL
        const url_cstr = try self.allocator.dupeZ(u8, self.uri_str);

        const url_result = c.curl_easy_setopt(handle, c.CURLOPT_URL, url_cstr.ptr);
        try set_fail(url_result, &curl_fail, .uri);

        // Enable WebSocket
        const connect_result = c.curl_easy_setopt(handle, c.CURLOPT_CONNECT_ONLY, @as(c_long, 2));
        try set_fail(connect_result, &curl_fail, .connect_only);

        // Set WebSocket options
        const ws_result = c.curl_easy_setopt(handle, c.CURLOPT_WS_OPTIONS, @as(c_long, 0));
        try set_fail(ws_result, &curl_fail, .ws_options);

        // SSL/TLS configuration - mimic what HTTP client does
        // Check if we should verify TLS certificates (same logic as HTTP client)
        // Access the app configuration through the browser
        const app = page.session.browser.app;
        const tls_verify_host = app.config.tls_verify_host;

        // default curl behavior for verification uses ssl.
        if (!tls_verify_host) {
            // Disable SSL verification like HTTP client does when tls_verify_host is false
            const verify_host_result = c.curl_easy_setopt(handle, c.CURLOPT_SSL_VERIFYHOST, @as(c_long, 0));
            try set_fail(verify_host_result, &curl_fail, .verify_host);
            const verify_peer_result = c.curl_easy_setopt(handle, c.CURLOPT_SSL_VERIFYPEER, @as(c_long, 0));
            try set_fail(verify_peer_result, &curl_fail, .verify_peer);
            log.warn(.ws, "ws SSL is DISABLED", .{});
        }

        // cookies
        var cookies: std.ArrayListUnmanaged(u8) = .{};
        try page.cookie_jar.forRequest(&self.uri, cookies.writer(self.allocator), .{
            .is_http = true,
            .origin_uri = &page.url.uri,
            .is_navigation = false, // WebSocket connections are not navigation
        });

        if (cookies.items.len > 0) {
            try cookies.append(self.allocator, 0); // null-terminate
            const cookie_result = c.curl_easy_setopt(handle, c.CURLOPT_COOKIE, @as([*c]const u8, @ptrCast(cookies.items.ptr)));
            try set_fail(cookie_result, &curl_fail, .cookie);
            log.info(.ws, "cookies set", .{});
        }

        // TODO: Set Sec-WebSocket-Protocol header.
        log.info(.ws, "ws handle init completed", .{});
    }

    fn attemptConnection(self: *WebSocket) !void {
        const page = self.page orelse return error.InvalidState;
        const handle = self.curl_handle orelse return error.InvalidState;

        if (self.ready_state != CONNECTING) {
            log.err(.ws, "ws invalid state", .{ .ready_state = self.ready_state });
            return error.InvalidState;
        }

        var curl_fail: ?CurlFail = null;
        errdefer if (curl_fail) |fail| fail.do_log();

        // Attempt to connect
        const connect_result = c.curl_easy_perform(handle);
        if (connect_result != 0) { self.ready_state = CLOSED; }
        try set_fail(connect_result, &curl_fail, .connect);

        // Connection successful
        log.info(.ws, "ws connection successful", .{});
        self.ready_state = OPEN;

        self.dispatchOpenEvent() catch |err| {
            log.err(.ws, "ws dispatch open failed", .{ .err = err });
            // Log the error but don't fail the connection
            // The connection is still valid even if event dispatch fails
        };

        // Schedule periodic message polling
        page.scheduler.add(self, receiveTask, 10, .{ .name = "WebSocket receive", .low_priority = true }) catch |err| {
            log.err(.ws, "ws schedule receive failed", .{ .err = err });
            // Log error but don't fail the connection
        };
    }

    fn dispatchOpenEvent(self: *WebSocket) !void {
        // Create and dispatch open event
        const event = parser.eventCreate() catch |err| {
            log.err(.ws, "ws eventCreate failed", .{ .err = err });
            // If we can't create an event, return the error
            return err;
        };
        defer parser.eventDestroy(event);

        parser.eventInit(event, "open", .{}) catch |err| {
            log.err(.ws, "ws eventInit failed", .{ .err = err });
            // If we can't initialize the event, return the error
            return err;
        };

        _ = parser.eventTargetDispatchEvent(@as(*parser.EventTarget, @ptrCast(self)), event) catch |err| {
            log.err(.ws, "ws dispatch failed", .{ .err = err });
            // If dispatch fails, return the error
            return err;
        };
        log.info(.ws, "ws event dispatched", .{});
    }

    fn dispatchErrorEvent(self: *WebSocket) !void {
        // Create and dispatch error event
        const event = try parser.eventCreate();
        defer parser.eventDestroy(event);
        try parser.eventInit(event, "error", .{});

        _ = try parser.eventTargetDispatchEvent(@as(*parser.EventTarget, @ptrCast(self)), event);
    }

    fn dispatchCloseEvent(self: *WebSocket, _: u16, _: []const u8) !void {
        // Create and dispatch close event
        const event = try parser.eventCreate();
        defer parser.eventDestroy(event);

        try parser.eventInit(event, "close", .{});
        // TODO: Set close event properties (code, reason, wasClean)
        _ = try parser.eventTargetDispatchEvent(@as(*parser.EventTarget, @ptrCast(self)), event);
    }

    // Task function for scheduler - attempts WebSocket connection
    fn connectionTask(ctx: *anyopaque) ?u32 {
        const self: *WebSocket = @ptrCast(@alignCast(ctx));
        // Safety check - ensure we're still in a valid state
        if (self.ready_state != CONNECTING) {
            log.info(.ws, "ws not connecting abort", .{});
            return null; // Don't attempt connection if not in connecting state
        }

        self.attemptConnection() catch |err| {
            log.err(.ws, "ws task connection failed", .{ .err = err });
            // If connection fails, set state and try to dispatch events safely
            self.ready_state = CLOSED;
        };

        log.info(.ws, "ws connection task completed", .{});
        return null; // Don't repeat this task
    }

    // Task function for scheduler - polls for incoming WebSocket messages
    fn receiveTask(ctx: *anyopaque) ?u32 {
        const self: *WebSocket = @ptrCast(@alignCast(ctx));

        if (self.ready_state != OPEN) return null; // Stop polling if not open

        self.receiveData() catch {};

        // Continue polling every 10ms if still open
        return if (self.ready_state == OPEN) 10 else null;
    }

    pub fn connect(self: *WebSocket) !void {
        try self.attemptConnection();
    }

    pub fn deinit(self: *WebSocket) void {
        if (self.curl_handle) |handle| {
            c.curl_easy_cleanup(handle);
            self.curl_handle = null;
        }
    }

    // Properties
    pub fn get_url(self: *const WebSocket) []const u8 {
        return self.uri_str;
    }

    pub fn get_readyState(self: *const WebSocket) u16 {
        return self.ready_state;
    }

    pub fn get_bufferedAmount(self: *const WebSocket) u32 {
        return self.buffered_amount;
    }

    pub fn get_extensions(self: *const WebSocket) []const u8 {
        return self.extensions;
    }

    pub fn get_protocol(self: *const WebSocket) []const u8 {
        return self.protocol;
    }

    pub fn get_binaryType(self: *const WebSocket) []const u8 {
        return self.binary_type;
    }

    pub fn set_binaryType(self: *WebSocket, value: []const u8) void {
        if (std.mem.eql(u8, value, "blob") or std.mem.eql(u8, value, "arraybuffer")) {
            self.binary_type = value;
        }
    }

    // Constants (static properties)
    pub fn get_CONNECTING(_: *const WebSocket) u16 {
        return CONNECTING;
    }

    pub fn get_OPEN(_: *const WebSocket) u16 {
        return OPEN;
    }

    pub fn get_CLOSING(_: *const WebSocket) u16 {
        return CLOSING;
    }

    pub fn get_CLOSED(_: *const WebSocket) u16 {
        return CLOSED;
    }

    // Methods
    pub fn _send(self: *WebSocket, data: []const u8) !void {
        // Safety checks
        if (self.ready_state != OPEN) {
            return error.InvalidState;
        }
        if (self.curl_handle == null) {
            return error.NoConnection;
        }

        const handle = self.curl_handle.?;
        var sent: usize = 0;

        // Send as text frame by default
        const result = c.curl_ws_send(handle, data.ptr, data.len, &sent, 0, // fragsize - 0 means send as single frame
            c.CURLWS_TEXT);

        if (result != c.CURLE_OK) {
            try self.dispatchErrorEvent();
            return error.SendFailed;
        }

        // Update buffered amount
        if (sent < data.len) {
            self.buffered_amount += @intCast(data.len - sent);
        }
    }

    pub fn _close(self: *WebSocket, code: ?u16, reason: ?[]const u8) !void {
        if (self.ready_state == CLOSING or self.ready_state == CLOSED) {
            return;
        }

        self.ready_state = CLOSING;

        if (self.curl_handle) |handle| {
            // Send close frame
            const close_code = code orelse 1000; // Normal closure
            const close_reason = reason orelse "";

            // Create close payload: 2-byte code + reason
            var close_payload: [2 + 125]u8 = undefined; // Max 125 bytes for close reason per WebSocket spec
            const code_bytes = std.mem.toBytes(std.mem.nativeToBig(u16, close_code));
            close_payload[0] = code_bytes[0];
            close_payload[1] = code_bytes[1];

            const reason_len = @min(close_reason.len, 125);
            @memcpy(close_payload[2 .. 2 + reason_len], close_reason[0..reason_len]);

            var sent: usize = 0;
            _ = c.curl_ws_send(handle, &close_payload, 2 + reason_len, &sent, 0, c.CURLWS_CLOSE);
        }

        self.ready_state = CLOSED;
        try self.dispatchCloseEvent(code orelse 1000, reason orelse "");

        // The receiveTask will automatically stop polling when ready_state != OPEN
    }

    // Receive data from WebSocket (to be called by the event loop)
    pub fn receiveData(self: *WebSocket) !void {
        // Safety checks
        if (self.curl_handle == null) {
            return error.NoConnection;
        }
        if (self.ready_state != OPEN) {
            return;
        }

        const handle = self.curl_handle.?;
        var buffer: [4096]u8 = undefined;
        var received: usize = 0;
        var meta: ?*const c.struct_curl_ws_frame = null;

        switch (c.curl_ws_recv(handle, &buffer, buffer.len, &received, &meta)) {
            c.CURLE_OK => {},
            c.CURLE_AGAIN => {
                // No data available right now, that's okay
                return;
            },
            c.CURLE_GOT_NOTHING => {
                // Connection closed
                self.ready_state = CLOSED;
                try self.dispatchCloseEvent(1006, "Connection closed unexpectedly");
            },
            else => {
                // Error occurred
                try self.dispatchErrorEvent();
                return error.ReceiveFailed;
            },
        }

        if (received == 0) return;
        const frame = meta orelse return;

        if ((frame.flags & c.CURLWS_CLOSE) != 0) {
            // Handle close frame
            var close_code: u16 = 1000;
            var close_reason: []const u8 = "";

            if (received >= 2) {
                close_code = std.mem.bigToNative(u16, @as(u16, @bitCast(buffer[0..2].*)));
                if (received > 2) {
                    close_reason = buffer[2..received];
                }
            }

            self.ready_state = CLOSED;
            try self.dispatchCloseEvent(close_code, close_reason);
            return;
        }

        if ((frame.flags & (c.CURLWS_TEXT | c.CURLWS_BINARY)) != 0) {
            // Handle message frame
            try self.dispatchMessageEvent(buffer[0..received], (frame.flags & c.CURLWS_BINARY) != 0);
        }
        // PING/PONG frames are handled automatically by libcurl
    }

    fn dispatchMessageEvent(self: *WebSocket, data: []const u8, is_binary: bool) !void {
        // Import MessageEvent from MessageChannel
        const page = self.page orelse return error.InvalidState;
        const MessageEvent = @import("../dom/MessageChannel.zig").MessageEvent;
        const v8 = @import("v8");

        // Create JavaScript string from the received data
        const js_string = v8.String.initUtf8(page.main_context.isolate, data);
        const js_obj = JsObject{
            .js_context = page.main_context,
            .js_obj = js_string.toValue().castTo(v8.Object),
        };
        const persistent_obj = try js_obj.persist();

        // Create MessageEvent with the data (like MessageChannel does)
        var message_event = MessageEvent{
            .proto = undefined,
            .data = persistent_obj,
            .source = null,
            .ports = &.{},
            .origin = "",
            .last_event_id = "",
        };

        // Initialize the proto event
        const event = try parser.eventCreate();
        defer parser.eventDestroy(event);
        try parser.eventInit(event, "message", .{});
        parser.eventSetInternalType(event, .message_event);
        message_event.proto = event.*;

        // Dispatch the message event
        _ = try parser.eventTargetDispatchEvent(@as(*parser.EventTarget, @ptrCast(self)), @as(*parser.Event, @ptrCast(&message_event)));

        // For now, ignore binary vs text distinction - treating everything as text
        _ = is_binary;
    }

    // Event handler properties
    pub fn get_onopen(self: *const WebSocket) ?Function {
        return self.onopen_cbk;
    }

    pub fn get_onerror(self: *const WebSocket) ?Function {
        return self.onerror_cbk;
    }

    pub fn get_onclose(self: *const WebSocket) ?Function {
        return self.onclose_cbk;
    }

    pub fn get_onmessage(self: *const WebSocket) ?Function {
        return self.onmessage_cbk;
    }

    pub fn set_onopen(self: *WebSocket, listener: ?EventHandler.Listener, page: *Page) !void {
        if (self.onopen_cbk) |cbk| try self.unregister("open", cbk.id);
        if (listener) |listen| {
            self.onopen_cbk = try self.register(page.arena, "open", listen);
        }
    }

    pub fn set_onerror(self: *WebSocket, listener: ?EventHandler.Listener, page: *Page) !void {
        if (self.onerror_cbk) |cbk| try self.unregister("error", cbk.id);
        if (listener) |listen| {
            self.onerror_cbk = try self.register(page.arena, "error", listen);
        }
    }

    pub fn set_onclose(self: *WebSocket, listener: ?EventHandler.Listener, page: *Page) !void {
        if (self.onclose_cbk) |cbk| try self.unregister("close", cbk.id);
        if (listener) |listen| {
            self.onclose_cbk = try self.register(page.arena, "close", listen);
        }
    }

    pub fn set_onmessage(self: *WebSocket, listener: ?EventHandler.Listener, page: *Page) !void {
        if (self.onmessage_cbk) |cbk| try self.unregister("message", cbk.id);
        if (listener) |listen| {
            self.onmessage_cbk = try self.register(page.arena, "message", listen);
        }
    }

    // Helper methods for event handling
    fn register(
        self: *WebSocket,
        alloc: std.mem.Allocator,
        typ: []const u8,
        listener: EventHandler.Listener,
    ) !?Function {
        const target = @as(*parser.EventTarget, @ptrCast(self));

        const eh = (try EventHandler.register(alloc, target, typ, listener, null)) orelse unreachable;
        return eh.callback;
    }

    fn unregister(self: *WebSocket, typ: []const u8, cbk_id: usize) !void {
        const et = @as(*parser.EventTarget, @ptrCast(self));
        const lst = try parser.eventTargetHasListener(et, typ, false, cbk_id);
        if (lst == null) {
            return;
        }
        try parser.eventTargetRemoveEventListener(et, typ, lst.?, false);
    }
};

pub const Interfaces = .{
    WebSocket,
};
