const std = @import("std");
const js = @import("js.zig");
const v8 = js.v8;

const log = @import("../../log.zig");
const Page = @import("../page.zig").Page;
const ScriptManager = @import("../ScriptManager.zig");

const types = @import("types.zig");
const Types = types.Types;
const Env = @import("Env.zig");
const Context = @import("Context.zig");

const ArenaAllocator = std.heap.ArenaAllocator;

const CONTEXT_ARENA_RETAIN = 1024 * 64;

// ExecutionWorld closely models a JS World.
// https://chromium.googlesource.com/chromium/src/+/master/third_party/blink/renderer/bindings/core/v8/V8BindingDesign.md#World
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/scripting/ExecutionWorld
const ExecutionWorld = @This();
env: *Env,

// Arena whose lifetime is for a single page load. Where
// the call_arena lives for a single function call, the context_arena
// lives for the lifetime of the entire page. The allocator will be
// owned by the Context, but the arena itself is owned by the ExecutionWorld
// so that we can re-use it from context to context.
context_arena: ArenaAllocator,

// Currently a context maps to a Browser's Page. Here though, it's only a
// mechanism to organization page-specific memory. The ExecutionWorld
// does all the work, but having all page-specific data structures
// grouped together helps keep things clean.
context: ?Context = null,

// no init, must be initialized via env.newExecutionWorld()

pub fn deinit(self: *ExecutionWorld) void {
    if (self.context != null) {
        self.removeContext();
    }

    self.context_arena.deinit();
}

// Only the top Context in the Main ExecutionWorld should hold a handle_scope.
// A v8.HandleScope is like an arena. Once created, any "Local" that
// v8 creates will be released (or at least, releasable by the v8 GC)
// when the handle_scope is freed.
// We also maintain our own "context_arena" which allows us to have
// all page related memory easily managed.
pub fn createContext(self: *ExecutionWorld, page: *Page, enter: bool, global_callback: ?js.GlobalMissingCallback) !*Context {
    std.debug.assert(self.context == null);
    const env = self.env;
    const isolate = env.isolate;
    const Global = @TypeOf(page.window);
    const templates = &self.env.templates;

    var v8_context: v8.Context = blk: {
        var temp_scope: v8.HandleScope = undefined;
        v8.HandleScope.init(&temp_scope, isolate);
        defer temp_scope.deinit();

        // Get the existing Window template
        const window_template = templates[types.getId(Global)];
        const global_template = window_template.getInstanceTemplate();

        // Configure the missing property interceptor on the Window template
        if (global_callback != null) {
            const configuration = v8.NamedPropertyHandlerConfiguration{
                .getter = struct {
                    fn callback(c_name: ?*const v8.C_Name, raw_info: ?*const v8.C_PropertyCallbackInfo) callconv(.c) u8 {
                        const info = v8.PropertyCallbackInfo.initFromV8(raw_info);
                        const context = Context.fromIsolate(info.getIsolate());

                        if (context.global_callback) |cb| {
                            const property = context.valueToString(.{ .handle = c_name.? }, .{}) catch "???";
                            if (cb.missing(property, context)) {
                                return v8.Intercepted.Yes;
                            }
                        }
                        return v8.Intercepted.No;
                    }
                }.callback,
                .flags = v8.PropertyHandlerFlags.NonMasking | v8.PropertyHandlerFlags.OnlyInterceptStrings,
            };
            global_template.setNamedProperty(configuration, null);
        }

        // Create the context using the Window template
        const context_local = v8.Context.init(isolate, global_template, null);
        const v8_context = v8.Persistent(v8.Context).init(isolate, context_local).castToContext();
        
        v8_context.enter();
        
        errdefer if (enter) v8_context.exit();
        defer if (!enter) v8_context.exit();

        break :blk v8_context;
    };

    var handle_scope: ?v8.HandleScope = null;
    if (enter) {
        handle_scope = @as(v8.HandleScope, undefined);
        v8.HandleScope.init(&handle_scope.?, isolate);
    }
    errdefer if (enter) handle_scope.?.deinit();

    const context_id = env.context_id;
    env.context_id = context_id + 1;

    self.context = Context{
        .page = page,
        .id = context_id,
        .isolate = isolate,
        .v8_context = v8_context,
        .templates = &env.templates,
        .meta_lookup = &env.meta_lookup,
        .handle_scope = handle_scope,
        .script_manager = &page.script_manager,
        .call_arena = page.call_arena,
        .arena = self.context_arena.allocator(),
        .global_callback = global_callback,
    };

    var context = &self.context.?;
    {
        // IMPORTANT: This must happen BEFORE any property setting that might trigger the interceptor
        const data = isolate.initBigIntU64(@intCast(@intFromPtr(context)));
        v8_context.setEmbedderData(1, data);
    }

    // Re-add all the Types (DOMException, Event, etc.) to the global object instance
    // We do this NOW, after EmbedderData is set, to avoid crashing if the interceptor fires.
    const global_obj = v8_context.getGlobal();
    inline for (Types, 0..) |s, i| {
        const Struct = s.defaultValue().?;
        const class_name = v8.String.initUtf8(isolate, comptime js.classNameForStruct(Struct));
        
        const constructor = templates[i].getFunction(v8_context);
        _ = global_obj.setValue(v8_context, class_name, constructor.toValue());
    }

    // Custom exception setup
    inline for (Types) |s| {
        const Struct = s.defaultValue().?;
        if (@hasDecl(Struct, "ErrorSet")) {
            const script = comptime js.classNameForStruct(Struct) ++ ".prototype.__proto__ = Error.prototype";
            _ = try context.exec(script, "errorSubclass");
        }
    }

    // Set complex attributes
    inline for (Types, 0..) |s, i| {
        const Struct = s.defaultValue().?;
        inline for (@typeInfo(Struct).@"struct".decls) |declaration| {
            const name = declaration.name;
            if (comptime name[0] == '_') {
                const value = @field(Struct, name);
                if (comptime js.isComplexAttributeType(@typeInfo(@TypeOf(value)))) {
                    const js_obj = templates[i].getFunction(v8_context).toObject();
                    const js_name = v8.String.initUtf8(isolate, name[1..]).toName();
                    const js_val = try context.zigValueToJs(value);
                    if (!js_obj.setValue(v8_context, js_name, js_val)) {
                        log.fatal(.app, "set class attribute", .{
                            .@"struct" = @typeName(Struct),
                            .name = name,
                        });
                    }
                }
            }
        }
    }

    try context.setupGlobal();
    return context;
}

pub fn removeContext(self: *ExecutionWorld) void {
    // Force running the micro task to drain the queue before reseting the
    // context arena.
    // Tasks in the queue are relying to the arena memory could be present in
    // the queue. Running them later could lead to invalid memory accesses.
    self.env.runMicrotasks();

    self.context.?.deinit();
    self.context = null;
    _ = self.context_arena.reset(.{ .retain_with_limit = CONTEXT_ARENA_RETAIN });
}

pub fn terminateExecution(self: *const ExecutionWorld) void {
    self.env.isolate.terminateExecution();
}

pub fn resumeExecution(self: *const ExecutionWorld) void {
    self.env.isolate.cancelTerminateExecution();
}
