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
const builtin = @import("builtin");

const net = std.net;
const posix = std.posix;

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const log = @import("log.zig");
const App = @import("app.zig").App;
const Browser = @import("browser/browser.zig").Browser;

const Http = @import("http/Http.zig");

const DevToolsClient = Client;
const CDP = @import("cdp/cdp.zig").CDPT(struct {
    pub const Client = *DevToolsClient;
});

const MAX_HTTP_REQUEST_SIZE = 4096;

// max message size
// +14 for max websocket payload overhead
// +140 for the max control packet that might be interleaved in a message
const MAX_MESSAGE_SIZE = 512 * 1024 + 14 + 140;

pub const Server = struct {
    browser: *Browser,
    shutdown: bool,
    allocator: Allocator,
    client: ?posix.socket_t,
    listener: ?posix.socket_t,
    json_version_response: []const u8,
    cdp_client: ?*Client = null,

    pub fn init(browser: *Browser, address: net.Address) !Server {
        const json_version_response = try buildJSONVersionResponse(browser.app.allocator, address);

        return .{
            .browser = browser,
            .client = null,
            .listener = null,
            .shutdown = false,
            .allocator = browser.app.allocator,
            .json_version_response = json_version_response,
        };
    }

    pub fn deinit(self: *Server) void {
        self.shutdown = true;
        if (self.listener) |listener| {
            posix.close(listener);
        }
        // *if* server.run is running, we should really wait for it to return
        // before existing from here.
        self.allocator.free(self.json_version_response);

        if (self.cdp_client) |cdp_client| {
            cdp_client.deinit();
        }
    }

    pub fn run(self: *Server, address: net.Address, timeout_ms: i32) !void {
        const flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
        const listener = try posix.socket(address.any.family, flags, posix.IPPROTO.TCP);
        self.listener = listener;

        try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        switch (builtin.os.tag) {
            .ios => {
                // TCP.NODELAY is not defined for iOS in posix module
                const TCP_NODELAY = 0x01;
                try posix.setsockopt(listener, posix.IPPROTO.TCP, TCP_NODELAY, &std.mem.toBytes(@as(c_int, 1)));
            },
            else => {
                if (@hasDecl(posix.TCP, "NODELAY")) {
                    try posix.setsockopt(listener, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
                }
            },
        }

        try posix.bind(listener, &address.any, address.getOsSockLen());
        try posix.listen(listener, 1);

        log.info(.app, "server running", .{ .address = address });
        while (true) {
            const socket = posix.accept(listener, null, null, 0) catch |err| {
                if (self.shutdown) {
                    return;
                }
                log.err(.app, "CDP accept", .{ .err = err });
                std.Thread.sleep(std.time.ns_per_s);
                continue;
            };

            self.client = socket;
            defer if (self.client) |s| {
                posix.close(s);
                self.client = null;
            };

            if (log.enabled(.app, .info)) {
                var client_address: std.net.Address = undefined;
                var socklen: posix.socklen_t = @sizeOf(net.Address);
                try std.posix.getsockname(socket, &client_address.any, &socklen);
                log.info(.app, "client connected", .{ .ip = client_address });
            }

            self.readLoop(socket, timeout_ms) catch |err| {
                log.err(.app, "CDP client loop", .{ .err = err });
            };
        }
    }

    fn readLoop(self: *Server, socket: posix.socket_t, timeout_ms: i32) !void {
        // This shouldn't be necessary, but the Client is HUGE (> 512KB) because
        // it has a large read buffer. I don't know why, but v8 crashes if this
        // is on the stack (and I assume it's related to its size).
        const client = try self.allocator.create(Client);
        defer self.allocator.destroy(client);

        client.* = try Client.init(socket, self);

        var http = &self.browser.app.http;
        http.monitorSocket(socket);

        std.debug.assert(client.mode == .http);
        while (true) {
            if (http.poll(timeout_ms) != .extra_socket) {
                log.info(.app, "CDP timeout", .{});
                return;
            }

            if (try client.readSocket() == false) {
                return;
            }

            if (client.mode == .cdp) {
                break; // switch to our CDP loop
            }
        }

        self.cdp_client = client;
        return;
    }
};

pub const Client = struct {
    // The client is initially serving HTTP requests but, under normal circumstances
    // should eventually be upgraded to a websocket connections
    mode: union(enum) {
        http: void,
        cdp: CDP,
    },

    server: *Server,
    reader: Reader(true),
    socket: posix.socket_t,
    socket_flags: usize,
    send_arena: ArenaAllocator,

    const EMPTY_PONG = [_]u8{ 138, 0 };

    // CLOSE, 2 length, code
    const CLOSE_NORMAL = [_]u8{ 136, 2, 3, 232 }; // code: 1000
    const CLOSE_TOO_BIG = [_]u8{ 136, 2, 3, 241 }; // 1009
    const CLOSE_PROTOCOL_ERROR = [_]u8{ 136, 2, 3, 234 }; //code: 1002
    // "private-use" close codes must be from 4000-49999
    const CLOSE_TIMEOUT = [_]u8{ 136, 2, 15, 160 }; // code: 4000

    fn init(socket: posix.socket_t, server: *Server) !Client {
        const socket_flags = try posix.fcntl(socket, posix.F.GETFL, 0);

        var reader = try Reader(true).init(server.allocator);
        errdefer reader.deinit();

        return .{
            .socket = socket,
            .server = server,
            .reader = reader,
            .mode = .{ .http = {} },
            .socket_flags = socket_flags,
            .send_arena = ArenaAllocator.init(server.allocator),
        };
    }

    fn deinit(self: *Client) void {
        switch (self.mode) {
            .cdp => |*cdp| cdp.deinit(),
            .http => {},
        }
        self.reader.deinit();
        self.send_arena.deinit();
    }

    pub fn readSocket(self: *Client) !bool {
        const n = posix.read(self.socket, self.readBuf()) catch |err| {
            log.warn(.app, "CDP read", .{ .err = err });
            return false;
        };

        if (n == 0) {
            log.info(.app, "CDP disconnect", .{});
            return false;
        }

        return self.processData(n) catch false;
    }

    fn readBuf(self: *Client) []u8 {
        return self.reader.readBuf();
    }

    fn processData(self: *Client, len: usize) !bool {
        self.reader.len += len;

        switch (self.mode) {
            .cdp => |*cdp| return self.processWebsocketMessage(cdp),
            .http => return self.processHTTPRequest(),
        }
    }

    fn processHTTPRequest(self: *Client) !bool {
        std.debug.assert(self.reader.pos == 0);
        const request = self.reader.buf[0..self.reader.len];

        if (request.len > MAX_HTTP_REQUEST_SIZE) {
            self.writeHTTPErrorResponse(413, "Request too large");
            return error.RequestTooLarge;
        }

        // we're only expecting [body-less] GET requests.
        if (std.mem.endsWith(u8, request, "\r\n\r\n") == false) {
            // we need more data, put any more data here
            return true;
        }

        // the next incoming data can go to the front of our buffer
        defer self.reader.len = 0;
        return self.handleHTTPRequest(request) catch |err| {
            switch (err) {
                error.NotFound => self.writeHTTPErrorResponse(404, "Not found"),
                error.InvalidRequest => self.writeHTTPErrorResponse(400, "Invalid request"),
                error.InvalidProtocol => self.writeHTTPErrorResponse(400, "Invalid HTTP protocol"),
                error.MissingHeaders => self.writeHTTPErrorResponse(400, "Missing required header"),
                error.InvalidUpgradeHeader => self.writeHTTPErrorResponse(400, "Unsupported upgrade type"),
                error.InvalidVersionHeader => self.writeHTTPErrorResponse(400, "Invalid websocket version"),
                error.InvalidConnectionHeader => self.writeHTTPErrorResponse(400, "Invalid connection header"),
                else => {
                    log.err(.app, "server 500", .{ .err = err, .req = request[0..@min(100, request.len)] });
                    self.writeHTTPErrorResponse(500, "Internal Server Error");
                },
            }
            return err;
        };
    }

    fn handleHTTPRequest(self: *Client, request: []u8) !bool {
        if (request.len < 18) {
            // 18 is [generously] the smallest acceptable HTTP request
            return error.InvalidRequest;
        }

        if (std.mem.eql(u8, request[0..4], "GET ") == false) {
            return error.NotFound;
        }

        const url_end = std.mem.indexOfScalarPos(u8, request, 4, ' ') orelse {
            return error.InvalidRequest;
        };

        const url = request[4..url_end];

        if (std.mem.eql(u8, url, "/")) {
            try self.upgradeConnection(request);
            return true;
        }

        if (std.mem.eql(u8, url, "/json/version")) {
            try self.send(self.server.json_version_response);
            return false;
        }

        if (std.mem.eql(u8, url, "/json/list?for_tab")) {
            // a list of all available websocket targets
            const response = try std.json.Stringify.valueAlloc(self.server.allocator, .{
                .{
                    .description = "",
                    .devtoolsFrontendUrl = "/devtools/inspector.html?ws=localhost:9583/devtools/page/0",
                    .id = "0",
                    .title = "Lightpanda",
                    .type = "page",
                    .url = self.server.browser.session.?.history.stack.items[self.server.browser.session.?.history.current.?].url, // NOTE: DevTools must be initialized after a page is available.
                    .webSocketDebuggerUrl = "ws://localhost:9583/devtools/page/0"
                }
            }, .{});
            defer self.server.allocator.free(response);

            const response_format =
            "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: Close\r\n" ++
            "Content-Type: application/json; charset=UTF-8\r\n\r\n" ++
            "{s}";
            const response_payload = try std.fmt.allocPrint(self.server.allocator, response_format, .{response.len, response});
            defer self.server.allocator.free(response_payload);
            
            try self.send(response_payload);
            
            return false;
        }

        if (std.mem.eql(u8, url, "/devtools/page/0")) {
            try self.upgradeConnection(request);
            return true;
        }

        log.err(.cdp, "requested url not found {s}", .{ url });

        return error.NotFound;
    }

    fn upgradeConnection(self: *Client, request: []u8) !void {
        // our caller already confirmed that we have a trailing \r\n\r\n
        const request_line_end = std.mem.indexOfScalar(u8, request, '\r') orelse unreachable;
        const request_line = request[0..request_line_end];

        if (!std.ascii.endsWithIgnoreCase(request_line, "http/1.1")) {
            return error.InvalidProtocol;
        }

        // we need to extract the sec-websocket-key value
        var key: []const u8 = "";

        // we need to make sure that we got all the necessary headers + values
        var required_headers: u8 = 0;

        // can't std.mem.split because it forces the iterated value to be const
        // (we could @constCast...)

        var buf = request[request_line_end + 2 ..];

        while (buf.len > 4) {
            const index = std.mem.indexOfScalar(u8, buf, '\r') orelse unreachable;
            const separator = std.mem.indexOfScalar(u8, buf[0..index], ':') orelse return error.InvalidRequest;

            const name = std.mem.trim(u8, toLower(buf[0..separator]), &std.ascii.whitespace);
            const value = std.mem.trim(u8, buf[(separator + 1)..index], &std.ascii.whitespace);

            if (std.mem.eql(u8, name, "upgrade")) {
                if (!std.ascii.eqlIgnoreCase("websocket", value)) {
                    return error.InvalidUpgradeHeader;
                }
                required_headers |= 1;
            } else if (std.mem.eql(u8, name, "sec-websocket-version")) {
                if (value.len != 2 or value[0] != '1' or value[1] != '3') {
                    return error.InvalidVersionHeader;
                }
                required_headers |= 2;
            } else if (std.mem.eql(u8, name, "connection")) {
                // find if connection header has upgrade in it, example header:
                // Connection: keep-alive, Upgrade
                if (std.ascii.indexOfIgnoreCase(value, "upgrade") == null) {
                    return error.InvalidConnectionHeader;
                }
                required_headers |= 4;
            } else if (std.mem.eql(u8, name, "sec-websocket-key")) {
                key = value;
                required_headers |= 8;
            }

            const next = index + 2;
            buf = buf[next..];
        }

        if (required_headers != 15) {
            return error.MissingHeaders;
        }

        // our caller has already made sure this request ended in \r\n\r\n
        // so it isn't something we need to check again

        const allocator = self.send_arena.allocator();

        const response = blk: {
            // Response to an ugprade request is always this, with
            // the Sec-Websocket-Accept value a spacial sha1 hash of the
            // request "sec-websocket-version" and a magic value.

            const template =
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: upgrade\r\n" ++
                "Sec-Websocket-Accept: 0000000000000000000000000000\r\n\r\n";

            // The response will be sent via the IO Loop and thus has to have its
            // own lifetime.
            const res = try allocator.dupe(u8, template);

            // magic response
            const key_pos = res.len - 32;
            var h: [20]u8 = undefined;
            var hasher = std.crypto.hash.Sha1.init(.{});
            hasher.update(key);
            // websocket spec always used this value
            hasher.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            hasher.final(&h);

            _ = std.base64.standard.Encoder.encode(res[key_pos .. key_pos + 28], h[0..]);

            break :blk res;
        };

        self.mode = .{ .cdp = try CDP.initWithBrowser(self.server.browser, self) };
        return self.send(response);
    }

    fn writeHTTPErrorResponse(self: *Client, comptime status: u16, comptime body: []const u8) void {
        const response = std.fmt.comptimePrint(
            "HTTP/1.1 {d} \r\nConnection: Close\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ status, body.len, body },
        );

        // we're going to close this connection anyways, swallowing any
        // error seems safe
        self.send(response) catch {};
    }

    fn processWebsocketMessage(self: *Client, cdp: *CDP) !bool {
        var reader = &self.reader;
        while (true) {
            const msg = reader.next() catch |err| {
                switch (err) {
                    error.TooLarge => self.send(&CLOSE_TOO_BIG) catch {},
                    error.NotMasked => self.send(&CLOSE_PROTOCOL_ERROR) catch {},
                    error.ReservedFlags => self.send(&CLOSE_PROTOCOL_ERROR) catch {},
                    error.InvalidMessageType => self.send(&CLOSE_PROTOCOL_ERROR) catch {},
                    error.ControlTooLarge => self.send(&CLOSE_PROTOCOL_ERROR) catch {},
                    error.InvalidContinuation => self.send(&CLOSE_PROTOCOL_ERROR) catch {},
                    error.NestedFragementation => self.send(&CLOSE_PROTOCOL_ERROR) catch {},
                    error.OutOfMemory => {}, // don't borther trying to send an error in this case
                }
                return err;
            } orelse break;

            switch (msg.type) {
                .pong => {},
                .ping => try self.sendPong(msg.data),
                .close => {
                    self.send(&CLOSE_NORMAL) catch {};
                    return false;
                },
                .text, .binary => if (cdp.handleMessage(msg.data) == false) {},
            }
            if (msg.cleanup_fragment) {
                reader.cleanup();
            }
        }

        // We might have read part of the next message. Our reader potentially
        // has to move data around in its buffer to make space.
        reader.compact();
        return true;
    }

    fn sendPong(self: *Client, data: []const u8) !void {
        if (data.len == 0) {
            return self.send(&EMPTY_PONG);
        }
        var header_buf: [10]u8 = undefined;
        const header = websocketHeader(&header_buf, .pong, data.len);

        const allocator = self.send_arena.allocator();
        var framed = try allocator.alloc(u8, header.len + data.len);
        @memcpy(framed[0..header.len], header);
        @memcpy(framed[header.len..], data);
        return self.send(framed);
    }

    // called by CDP
    // Websocket frames have a variable lenght header. For server-client,
    // it could be anywhere from 2 to 10 bytes. Our IO.Loop doesn't have
    // writev, so we need to get creative. We'll JSON serialize to a
    // buffer, where the first 10 bytes are reserved. We can then backfill
    // the header and send the slice.
    pub fn sendJSON(self: *Client, message: anytype, opts: std.json.Stringify.Options) !void {
        const allocator = self.send_arena.allocator();

        var aw = try std.Io.Writer.Allocating.initCapacity(allocator, 512);

        // reserve space for the maximum possible header
        try aw.writer.writeAll(&.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
        try std.json.Stringify.value(message, opts, &aw.writer);
        const framed = fillWebsocketHeader(aw.toArrayList());
        return self.send(framed);
    }

    pub fn sendJSONRaw(
        self: *Client,
        buf: std.ArrayListUnmanaged(u8),
    ) !void {
        // Dangerous API!. We assume the caller has reserved the first 10
        // bytes in `buf`.
        const framed = fillWebsocketHeader(buf);
        return self.send(framed);
    }

    fn send(self: *Client, data: []const u8) !void {
        var pos: usize = 0;
        defer _ = self.send_arena.reset(.{ .retain_with_limit = 1024 * 32 });

        while (pos < data.len) {
            const written = posix.write(self.socket, data[pos..]) catch |err| return err;

            if (written == 0) {
                return error.Closed;
            }
            pos += written;
        }
    }
};

// WebSocket message reader. Given websocket message, acts as an iterator that
// can return zero or more Messages. When next returns null, any incomplete
// message will remain in reader.data
fn Reader(comptime EXPECT_MASK: bool) type {
    return struct {
        allocator: Allocator,

        // position in buf of the start of the next message
        pos: usize = 0,

        // position in buf up until where we have valid data
        // (any new reads must be placed after this)
        len: usize = 0,

        // we add 140 to allow 1 control message (ping/pong/close) to be
        // fragmented into a normal message.
        buf: []u8,

        fragments: ?Fragments = null,

        const Self = @This();

        fn init(allocator: Allocator) !Self {
            const buf = try allocator.alloc(u8, 16 * 1024);
            return .{
                .buf = buf,
                .allocator = allocator,
            };
        }

        fn deinit(self: *Self) void {
            self.cleanup();
            self.allocator.free(self.buf);
        }

        fn cleanup(self: *Self) void {
            if (self.fragments) |*f| {
                f.message.deinit(self.allocator);
                self.fragments = null;
            }
        }

        fn readBuf(self: *Self) []u8 {
            // We might have read a partial http or websocket message.
            // Subsequent reads must read from where we left off.
            return self.buf[self.len..];
        }

        fn next(self: *Self) !?Message {
            LOOP: while (true) {
                var buf = self.buf[self.pos..self.len];

                const length_of_len, const message_len = extractLengths(buf) orelse {
                    // we don't have enough bytes
                    return null;
                };

                const byte1 = buf[0];

                if (byte1 & 112 != 0) {
                    return error.ReservedFlags;
                }

                if (comptime EXPECT_MASK) {
                    if (buf[1] & 128 != 128) {
                        // client -> server messages _must_ be masked
                        return error.NotMasked;
                    }
                } else if (buf[1] & 128 != 0) {
                    // server -> client are never masked
                    return error.Masked;
                }

                var is_control = false;
                var is_continuation = false;
                var message_type: Message.Type = undefined;
                switch (byte1 & 15) {
                    0 => is_continuation = true,
                    1 => message_type = .text,
                    2 => message_type = .binary,
                    8 => {
                        is_control = true;
                        message_type = .close;
                    },
                    9 => {
                        is_control = true;
                        message_type = .ping;
                    },
                    10 => {
                        is_control = true;
                        message_type = .pong;
                    },
                    else => return error.InvalidMessageType,
                }

                if (is_control) {
                    if (message_len > 125) {
                        return error.ControlTooLarge;
                    }
                } else if (message_len > MAX_MESSAGE_SIZE) {
                    return error.TooLarge;
                } else if (message_len > self.buf.len) {
                    const len = self.buf.len;
                    self.buf = try growBuffer(self.allocator, self.buf, message_len);
                    buf = self.buf[0..len];
                    // we need more data
                    return null;
                } else if (buf.len < message_len) {
                    // we need more data
                    return null;
                }

                // prefix + length_of_len + mask
                const header_len = 2 + length_of_len + if (comptime EXPECT_MASK) 4 else 0;

                const payload = buf[header_len..message_len];
                if (comptime EXPECT_MASK) {
                    mask(buf[header_len - 4 .. header_len], payload);
                }

                // whatever happens after this, we know where the next message starts
                self.pos += message_len;

                const fin = byte1 & 128 == 128;

                if (is_continuation) {
                    const fragments = &(self.fragments orelse return error.InvalidContinuation);
                    if (fragments.message.items.len + message_len > MAX_MESSAGE_SIZE) {
                        return error.TooLarge;
                    }

                    try fragments.message.appendSlice(self.allocator, payload);

                    if (fin == false) {
                        // maybe we have more parts of the message waiting
                        continue :LOOP;
                    }

                    // this continuation is done!
                    return .{
                        .type = fragments.type,
                        .data = fragments.message.items,
                        .cleanup_fragment = true,
                    };
                }

                const can_be_fragmented = message_type == .text or message_type == .binary;
                if (self.fragments != null and can_be_fragmented) {
                    // if this isn't a continuation, then we can't have fragments
                    return error.NestedFragementation;
                }

                if (fin == false) {
                    if (can_be_fragmented == false) {
                        return error.InvalidContinuation;
                    }

                    // not continuation, and not fin. It has to be the first message
                    // in a fragmented message.
                    var fragments = Fragments{ .message = .{}, .type = message_type };
                    try fragments.message.appendSlice(self.allocator, payload);
                    self.fragments = fragments;
                    continue :LOOP;
                }

                return .{
                    .data = payload,
                    .type = message_type,
                    .cleanup_fragment = false,
                };
            }
        }

        fn extractLengths(buf: []const u8) ?struct { usize, usize } {
            if (buf.len < 2) {
                return null;
            }

            const length_of_len: usize = switch (buf[1] & 127) {
                126 => 2,
                127 => 8,
                else => 0,
            };

            if (buf.len < length_of_len + 2) {
                // we definitely don't have enough buf yet
                return null;
            }

            const message_len = switch (length_of_len) {
                2 => @as(u16, @intCast(buf[3])) | @as(u16, @intCast(buf[2])) << 8,
                8 => @as(u64, @intCast(buf[9])) | @as(u64, @intCast(buf[8])) << 8 | @as(u64, @intCast(buf[7])) << 16 | @as(u64, @intCast(buf[6])) << 24 | @as(u64, @intCast(buf[5])) << 32 | @as(u64, @intCast(buf[4])) << 40 | @as(u64, @intCast(buf[3])) << 48 | @as(u64, @intCast(buf[2])) << 56,
                else => buf[1] & 127,
            } + length_of_len + 2 + if (comptime EXPECT_MASK) 4 else 0; // +2 for header prefix, +4 for mask;

            return .{ length_of_len, message_len };
        }

        // This is called after we've processed complete websocket messages (this
        // only applies to websocket messages).
        // There are three cases:
        // 1 - We don't have any incomplete data (for a subsequent message) in buf.
        //     This is the easier to handle, we can set pos & len to 0.
        // 2 - We have part of the next message, but we know it'll fit in the
        //     remaining buf. We don't need to do anything
        // 3 - We have part of the next message, but either it won't fight into the
        //     remaining buffer, or we don't know (because we don't have enough
        //     of the header to tell the length). We need to "compact" the buffer
        fn compact(self: *Self) void {
            const pos = self.pos;
            const len = self.len;

            std.debug.assert(pos <= len);

            // how many (if any) partial bytes do we have
            const partial_bytes = len - pos;

            if (partial_bytes == 0) {
                // We have no partial bytes. Setting these to 0 ensures that we
                // get the best utilization of our buffer
                self.pos = 0;
                self.len = 0;
                return;
            }

            const partial = self.buf[pos..len];

            // If we have enough bytes of the next message to tell its length
            // we'll be able to figure out whether we need to do anything or not.
            if (extractLengths(partial)) |length_meta| {
                const next_message_len = length_meta.@"1";
                // if this isn't true, then we have a full message and it
                // should have been processed.
                std.debug.assert(next_message_len > partial_bytes);

                const missing_bytes = next_message_len - partial_bytes;

                const free_space = self.buf.len - len;
                if (missing_bytes < free_space) {
                    // we have enough space in our buffer, as is,
                    return;
                }
            }

            // We're here because we either don't have enough bytes of the next
            // message, or we know that it won't fit in our buffer as-is.
            std.mem.copyForwards(u8, self.buf, partial);
            self.pos = 0;
            self.len = partial_bytes;
        }
    };
}

fn growBuffer(allocator: Allocator, buf: []u8, required_capacity: usize) ![]u8 {
    // from std.ArrayList
    var new_capacity = buf.len;
    while (true) {
        new_capacity +|= new_capacity / 2 + 8;
        if (new_capacity >= required_capacity) break;
    }

    log.debug(.app, "CDP buffer growth", .{ .from = buf.len, .to = new_capacity });

    if (allocator.resize(buf, new_capacity)) {
        return buf.ptr[0..new_capacity];
    }
    const new_buffer = try allocator.alloc(u8, new_capacity);
    @memcpy(new_buffer[0..buf.len], buf);
    allocator.free(buf);
    return new_buffer;
}

const Fragments = struct {
    type: Message.Type,
    message: std.ArrayListUnmanaged(u8),
};

const Message = struct {
    type: Type,
    data: []const u8,
    cleanup_fragment: bool,

    const Type = enum {
        text,
        binary,
        close,
        ping,
        pong,
    };
};

// These are the only websocket types that we're currently sending
const OpCode = enum(u8) {
    text = 128 | 1,
    close = 128 | 8,
    pong = 128 | 10,
};

fn fillWebsocketHeader(buf: std.ArrayListUnmanaged(u8)) []const u8 {
    // can't use buf[0..10] here, because the header length
    // is variable. If it's just 2 bytes, for example, we need the
    // framed message to be:
    //     h1, h2, data
    // If we use buf[0..10], we'd get:
    //    h1, h2, 0, 0, 0, 0, 0, 0, 0, 0, data

    var header_buf: [10]u8 = undefined;

    // -10 because we reserved 10 bytes for the header above
    const header = websocketHeader(&header_buf, .text, buf.items.len - 10);
    const start = 10 - header.len;

    const message = buf.items;
    @memcpy(message[start..10], header);
    return message[start..];
}

// makes the assumption that our caller reserved the first
// 10 bytes for the header
fn websocketHeader(buf: []u8, op_code: OpCode, payload_len: usize) []const u8 {
    std.debug.assert(buf.len == 10);

    const len = payload_len;
    buf[0] = 128 | @intFromEnum(op_code); // fin | opcode

    if (len <= 125) {
        buf[1] = @intCast(len);
        return buf[0..2];
    }

    if (len < 65536) {
        buf[1] = 126;
        buf[2] = @intCast((len >> 8) & 0xFF);
        buf[3] = @intCast(len & 0xFF);
        return buf[0..4];
    }

    buf[1] = 127;
    buf[2] = 0;
    buf[3] = 0;
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = @intCast((len >> 24) & 0xFF);
    buf[7] = @intCast((len >> 16) & 0xFF);
    buf[8] = @intCast((len >> 8) & 0xFF);
    buf[9] = @intCast(len & 0xFF);
    return buf[0..10];
}

// Utils
// --------

fn buildJSONVersionResponse(
    allocator: Allocator,
    address: net.Address,
) ![]const u8 {
    const body_format = "{{\"Browser\": \"Chrome/72.0.3601.0\",\"Protocol-Version\": \"1.3\",\"User-Agent\": \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3601.0 Safari/537.36\",\"V8-Version\": \"7.2.233\",\"WebKit-Version\":\"537.36 (@cfede9db1d154de0468cb0538479f34c0755a0f4)\",\"webSocketDebuggerUrl\": \"ws://{f}/\"}}";
    const body_len = std.fmt.count(body_format, .{address});

    // We send a Connection: Close (and actually close the connection)
    // because chromedp (Go driver) sends a request to /json/version and then
    // does an upgrade request, on a different connection. Since we only allow
    // 1 connection at a time, the upgrade connection doesn't proceed until we
    // timeout the /json/version. So, instead of waiting for that, we just
    // always close HTTP requests.
    const response_format =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Connection: Close\r\n" ++
        "Content-Type: application/json; charset=UTF-8\r\n\r\n" ++
        body_format;
    return try std.fmt.allocPrint(allocator, response_format, .{ body_len, address });
}

fn timestamp() u32 {
    return @import("datetime.zig").timestamp();
}

// In-place string lowercase
fn toLower(str: []u8) []u8 {
    for (str, 0..) |c, i| {
        str[i] = std.ascii.toLower(c);
    }
    return str;
}

// Zig is in a weird backend transition right now. Need to determine if
// SIMD is even available.
const backend_supports_vectors = switch (builtin.zig_backend) {
    .stage2_llvm, .stage2_c => true,
    else => false,
};

// Websocket messages from client->server are masked using a 4 byte XOR mask
fn mask(m: []const u8, payload: []u8) void {
    var data = payload;

    if (!comptime backend_supports_vectors) return simpleMask(m, data);

    const vector_size = std.simd.suggestVectorLength(u8) orelse @sizeOf(usize);
    if (data.len >= vector_size) {
        const mask_vector = std.simd.repeat(vector_size, @as(@Vector(4, u8), m[0..4].*));
        while (data.len >= vector_size) {
            const slice = data[0..vector_size];
            const masked_data_slice: @Vector(vector_size, u8) = slice.*;
            slice.* = masked_data_slice ^ mask_vector;
            data = data[vector_size..];
        }
    }
    simpleMask(m, data);
}

// Used when SIMD isn't available, or for any remaining part of the message
// which is too small to effectively use SIMD.
fn simpleMask(m: []const u8, payload: []u8) void {
    for (payload, 0..) |b, i| {
        payload[i] = b ^ m[i & 3];
    }
}