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
    url: []const u8 = "",
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

    pub fn constructor(url: []const u8, protocols: ?[]const []const u8, page: *Page) !*WebSocket {
        // Validate URL format
        const uri = std.Uri.parse(url) catch |err| {
            return err;
        };

        // Check if it's a valid WebSocket URL
        if (!std.mem.eql(u8, uri.scheme, "ws") and !std.mem.eql(u8, uri.scheme, "wss")) {
            return error.InvalidURL;
        }

        // Allocate WebSocket on heap for stable address
        const websocket = try page.arena.create(WebSocket);
        websocket.* = WebSocket{
            .url = try page.arena.dupe(u8, url),
            .protocols = if (protocols) |p| try page.arena.dupe([]const u8, p) else &.{},
            .ready_state = CONNECTING,
            .page = page,
            .allocator = page.arena,
        };

        // Initialize libcurl handle but don't connect yet
        std.debug.print("WebSocket constructor: Initializing handle\n", .{});
        websocket.initHandle() catch |err| {
            std.debug.print("WebSocket constructor: initHandle failed: {}\n", .{err});
            return err;
        };

        // Schedule asynchronous connection attempt
        std.debug.print("WebSocket constructor: Scheduling connection task\n", .{});
        try page.scheduler.add(websocket, connectionTask, 0, .{ .name = "WebSocket connection" });

        std.debug.print("WebSocket constructor: WebSocket created successfully\n", .{});
        return websocket;
    }

    fn initHandle(self: *WebSocket) !void {
        std.debug.print("WebSocket initHandle: Creating curl handle\n", .{});
        // Create curl handle
        self.curl_handle = c.curl_easy_init();
        if (self.curl_handle == null) {
            std.debug.print("WebSocket initHandle: curl_easy_init failed\n", .{});
            return error.CurlInitFailed;
        }
        std.debug.print("WebSocket initHandle: curl handle created successfully\n", .{});

        errdefer {
            if (self.curl_handle) |handle| {
                c.curl_easy_cleanup(handle);
                self.curl_handle = null;
            }
        }

        const handle = self.curl_handle.?;

        std.debug.print("WebSocket initHandle: Setting URL: {s}\n", .{self.url});
        // Set URL
        const url_cstr = self.allocator.dupeZ(u8, self.url) catch |err| {
            std.debug.print("WebSocket initHandle: dupeZ failed: {}\n", .{err});
            return err;
        };
        const url_result = c.curl_easy_setopt(handle, c.CURLOPT_URL, url_cstr.ptr);
        std.debug.print("WebSocket initHandle: CURLOPT_URL result: {}\n", .{url_result});

        std.debug.print("WebSocket initHandle: Setting WebSocket options\n", .{});
        // Enable WebSocket
        const connect_result = c.curl_easy_setopt(handle, c.CURLOPT_CONNECT_ONLY, @as(c_long, 2));
        std.debug.print("WebSocket initHandle: CURLOPT_CONNECT_ONLY result: {}\n", .{connect_result});

        // Set WebSocket options
        const ws_result = c.curl_easy_setopt(handle, c.CURLOPT_WS_OPTIONS, @as(c_long, 0));
        std.debug.print("WebSocket initHandle: CURLOPT_WS_OPTIONS result: {}\n", .{ws_result});

        // SSL/TLS configuration - mimic what HTTP client does
        // Check if we should verify TLS certificates (same logic as HTTP client)
        if (self.page) |page| {
            // Access the app configuration through the browser
            const app = page.session.browser.app;
            const tls_verify_host = app.config.tls_verify_host;
            std.debug.print("WebSocket initHandle: Setting SSL options (tls_verify_host = {})\n", .{tls_verify_host});

            if (tls_verify_host) {
                // Use CA certificates - default curl behavior for verification
                std.debug.print("WebSocket initHandle: Enabling SSL certificate verification\n", .{});
                // No need to set anything - curl verifies by default
            } else {
                // Disable SSL verification like HTTP client does when tls_verify_host is false
                std.debug.print("WebSocket initHandle: Disabling SSL certificate verification\n", .{});
                _ = c.curl_easy_setopt(handle, c.CURLOPT_SSL_VERIFYHOST, @as(c_long, 0));
                _ = c.curl_easy_setopt(handle, c.CURLOPT_SSL_VERIFYPEER, @as(c_long, 0));
            }
        }

        // Set cookies from cookie jar (same as HTTP client does)
        if (self.page) |page| {
            if (std.Uri.parse(self.url)) |parsed_uri| {
                var cookies: std.ArrayListUnmanaged(u8) = .{};
                if (page.cookie_jar.forRequest(&parsed_uri, cookies.writer(self.allocator), .{
                    .is_http = true,
                    .origin_uri = &parsed_uri,
                    .is_navigation = false, // WebSocket connections are not navigation
                })) {
                    if (cookies.append(self.allocator, 0)) { // null terminate
                        if (cookies.items.len > 1) { // Only set if we have cookies (more than just null terminator)
                            std.debug.print("WebSocket initHandle: Setting cookies: {s}\n", .{cookies.items[0..cookies.items.len-1]});
                            _ = c.curl_easy_setopt(handle, c.CURLOPT_COOKIE, @as([*c]const u8, @ptrCast(cookies.items.ptr)));
                        } else {
                            std.debug.print("WebSocket initHandle: No cookies to set\n", .{});
                        }
                    } else |err| {
                        std.debug.print("WebSocket initHandle: Failed to null-terminate cookies: {}\n", .{err});
                    }
                } else |err| {
                    std.debug.print("WebSocket initHandle: Failed to get cookies: {}\n", .{err});
                }
            } else |err| {
                std.debug.print("WebSocket initHandle: Failed to parse URL for cookies: {}\n", .{err});
            }
        }

        // Set protocols if provided
        if (self.protocols.len > 0) {
            std.debug.print("WebSocket initHandle: TODO: Set protocols\n", .{});
            // TODO: Set Sec-WebSocket-Protocol header
            // For now, skip protocol setting to avoid ArrayList usage
        }

        std.debug.print("WebSocket initHandle: Handle initialization completed successfully\n", .{});
    }

    fn attemptConnection(self: *WebSocket) !void {
        std.debug.print("WebSocket attemptConnection: Starting connection attempt\n", .{});

        if (self.curl_handle == null or self.ready_state != CONNECTING) {
            std.debug.print("WebSocket attemptConnection: Invalid state - handle: {}, ready_state: {}\n", .{ self.curl_handle != null, self.ready_state });
            return error.InvalidState;
        }

        const handle = self.curl_handle.?;

        std.debug.print("WebSocket attemptConnection: Calling curl_easy_perform\n", .{});
        // Attempt to connect
        const result = c.curl_easy_perform(handle);
        std.debug.print("WebSocket attemptConnection: curl_easy_perform result: {}\n", .{result});

        if (result == c.CURLE_OK) {
            std.debug.print("WebSocket attemptConnection: Connection successful, setting state to OPEN\n", .{});
            // Connection successful
            self.ready_state = OPEN;

            std.debug.print("WebSocket attemptConnection: Dispatching open event\n", .{});
            // Try to dispatch open event, but don't fail the connection if event dispatch fails
            self.dispatchOpenEvent() catch |err| {
                std.debug.print("WebSocket attemptConnection: dispatchOpenEvent failed: {}\n", .{err});
                // Log the error but don't fail the connection
                // The connection is still valid even if event dispatch fails
            };

            std.debug.print("WebSocket attemptConnection: Scheduling receive task\n", .{});
            // Schedule periodic message polling
            if (self.page) |page| {
                page.scheduler.add(self, receiveTask, 10, .{ .name = "WebSocket receive", .low_priority = true }) catch |err| {
                    std.debug.print("WebSocket attemptConnection: Failed to schedule receive task: {}\n", .{err});
                    // Log error but don't fail the connection
                };
            }
        } else {
            std.debug.print("WebSocket attemptConnection: Connection failed with curl error: {}\n", .{result});
            // Connection failed
            self.ready_state = CLOSED;
            // Only dispatch events if we're not being called from a task context
            // Event dispatching should happen from the main thread/context
        }
        std.debug.print("WebSocket attemptConnection: Connection attempt completed\n", .{});
    }

    fn dispatchOpenEvent(self: *WebSocket) !void {
        std.debug.print("WebSocket dispatchOpenEvent: Creating event\n", .{});
        // Create and dispatch open event
        const event = parser.eventCreate() catch |err| {
            std.debug.print("WebSocket dispatchOpenEvent: eventCreate failed: {}\n", .{err});
            // If we can't create an event, return the error
            return err;
        };
        defer parser.eventDestroy(event);

        std.debug.print("WebSocket dispatchOpenEvent: Initializing event\n", .{});
        parser.eventInit(event, "open", .{}) catch |err| {
            std.debug.print("WebSocket dispatchOpenEvent: eventInit failed: {}\n", .{err});
            // If we can't initialize the event, return the error
            return err;
        };

        std.debug.print("WebSocket dispatchOpenEvent: Dispatching event\n", .{});
        _ = parser.eventTargetDispatchEvent(@as(*parser.EventTarget, @ptrCast(self)), event) catch |err| {
            std.debug.print("WebSocket dispatchOpenEvent: eventTargetDispatchEvent failed: {}\n", .{err});
            // If dispatch fails, return the error
            return err;
        };
        std.debug.print("WebSocket dispatchOpenEvent: Event dispatched successfully\n", .{});
    }

    fn dispatchErrorEvent(self: *WebSocket) !void {
        // Create and dispatch error event
        const event = parser.eventCreate() catch |err| {
            // If we can't create an event, just return - don't crash
            return err;
        };
        defer parser.eventDestroy(event);

        parser.eventInit(event, "error", .{}) catch |err| {
            // If we can't initialize the event, return the error
            return err;
        };

        _ = parser.eventTargetDispatchEvent(@as(*parser.EventTarget, @ptrCast(self)), event) catch |err| {
            // If dispatch fails, return the error
            return err;
        };
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

        std.debug.print("WebSocket connectionTask: Starting connection attempt\n", .{});

        // Safety check - ensure we're still in a valid state
        if (self.ready_state != CONNECTING) {
            std.debug.print("WebSocket connectionTask: Not in CONNECTING state, aborting\n", .{});
            return null; // Don't attempt connection if not in connecting state
        }

        self.attemptConnection() catch |err| {
            std.debug.print("WebSocket connectionTask: Connection failed with error: {}\n", .{err});
            // If connection fails, set state and try to dispatch events safely
            self.ready_state = CLOSED;

            // Only dispatch events if we have a valid page context
            if (self.page != null) {
                // Use a safer approach - just log the error for now
                // Event dispatching from task context can be problematic
            }
        };
        std.debug.print("WebSocket connectionTask: Connection task completed\n", .{});
        return null; // Don't repeat this task
    }

    // Task function for scheduler - polls for incoming WebSocket messages
    fn receiveTask(ctx: *anyopaque) ?u32 {
        const self: *WebSocket = @ptrCast(@alignCast(ctx));

        // Only poll if connection is open
        if (self.ready_state != OPEN) {
            return null; // Stop polling if not open
        }

        self.receiveData() catch {};

        // Continue polling every 10ms if still open
        if (self.ready_state == OPEN) {
            return 10;
        } else {
            return null; // Stop polling if connection closed
        }
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
        return self.url;
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
        const result = c.curl_ws_send(
            handle,
            data.ptr,
            data.len,
            &sent,
            0, // fragsize - 0 means send as single frame
            c.CURLWS_TEXT
        );

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
            @memcpy(close_payload[2..2 + reason_len], close_reason[0..reason_len]);

            var sent: usize = 0;
            _ = c.curl_ws_send(
                handle,
                &close_payload,
                2 + reason_len,
                &sent,
                0,
                c.CURLWS_CLOSE
            );
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

        const result = c.curl_ws_recv(handle, &buffer, buffer.len, &received, &meta);

        switch (result) {
            c.CURLE_OK => {
                if (received > 0 and meta != null) {
                    const frame = meta.?;

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

                    } else if ((frame.flags & (c.CURLWS_TEXT | c.CURLWS_BINARY)) != 0) {
                        // Handle message frame
                        try self.dispatchMessageEvent(buffer[0..received], (frame.flags & c.CURLWS_BINARY) != 0);
                    }
                    // PING/PONG frames are handled automatically by libcurl
                }
            },
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
            }
        }
    }

    fn dispatchMessageEvent(self: *WebSocket, data: []const u8, is_binary: bool) !void {
        // Import MessageEvent from MessageChannel
        const MessageEvent = @import("../dom/MessageChannel.zig").MessageEvent;
        const v8 = @import("v8");

        if (self.page) |page| {
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
            _ = try parser.eventTargetDispatchEvent(
                @as(*parser.EventTarget, @ptrCast(self)),
                @as(*parser.Event, @ptrCast(&message_event))
            );

            // For now, ignore binary vs text distinction - treating everything as text
            _ = is_binary;
        }
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