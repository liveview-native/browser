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
const log = @import("../../log.zig");

const parser = @import("../netsurf.zig");
const Event = @import("event.zig").Event;

// https://developer.mozilla.org/en-US/docs/Web/API/UIEvent
pub const UIEvent = struct {
    pub const Self = parser.UIEvent;
    pub const prototype = *Event;

    const UIEventInit = struct {
        view: ?*parser.UIEvent = null,
        detail: i32 = 0,
    };

    pub fn constructor(event_type: []const u8, opts_: ?UIEventInit) !*parser.UIEvent {
        const opts = opts_ orelse UIEventInit{};

        const ui_event = try parser.uiEventCreate();
        parser.eventSetInternalType(@ptrCast(ui_event), .ui_event);

        try parser.uiEventInit(ui_event, event_type, .{
            .view = @ptrCast(@alignCast(opts.view)),
            .detail = opts.detail
        });

        return ui_event;
    }

    pub fn get_view(self: *parser.UIEvent) !?*parser.EventTarget {
        return @ptrCast(@alignCast(self.view));
    }
    
    pub fn get_detail(self: *parser.UIEvent) i32 {
        return self.detail;
    }
};
