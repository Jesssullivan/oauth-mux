//! Bounded native I/O outside the lifecycle actor. Announcement has a separate
//! lane so its adapter callback cannot wait behind announcements using every
//! native worker. Jobs and results stay owned until the actor takes completion.
const std = @import("std");

pub const capacity = 8;
pub const Lane = enum { announcement, continuation };
pub const Job = struct {
    lane: Lane,
    context: *anyopaque,
    run: *const fn (*anyopaque, bool) void,
};
pub const Wake = struct { context: *anyopaque, signal: *const fn (*anyopaque) void };

pub const Supervisor = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    wake: Wake,
    mutex: std.Io.Mutex = .init,
    condition: std.Io.Condition = .init,
    queue: [capacity]?*Job = @splat(null),
    queue_len: usize = 0,
    completed: [capacity]?*Job = @splat(null),
    completed_head: usize = 0,
    completed_len: usize = 0,
    outstanding: usize = 0,
    ready: std.atomic.Value(usize) = .init(0),
    stopping: bool = false,
    threads: [2]?std.Thread = @splat(null),

    pub fn create(io: std.Io, allocator: std.mem.Allocator, wake: Wake) !*Supervisor {
        const self = try allocator.create(Supervisor);
        self.* = .{ .allocator = allocator, .io = io, .wake = wake };
        errdefer allocator.destroy(self);
        self.threads[0] = try std.Thread.spawn(.{}, worker, .{ self, Lane.announcement });
        errdefer {
            self.stop();
            self.threads[0].?.join();
        }
        self.threads[1] = try std.Thread.spawn(.{}, worker, .{ self, Lane.continuation });
        return self;
    }

    pub fn enqueue(self: *Supervisor, job: *Job) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) return error.ServiceStopping;
        if (self.outstanding == capacity) return error.NativeWorkCapacity;
        self.queue[self.queue_len] = job;
        self.queue_len += 1;
        self.outstanding += 1;
        self.condition.broadcast(self.io);
    }

    pub fn hasCompleted(self: *const Supervisor) bool {
        return self.ready.load(.acquire) != 0;
    }

    pub fn takeCompleted(self: *Supervisor) ?*Job {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.completed_len == 0) return null;
        const job = self.completed[self.completed_head].?;
        self.completed[self.completed_head] = null;
        self.completed_head = (self.completed_head + 1) % capacity;
        self.completed_len -= 1;
        self.outstanding -= 1;
        self.ready.store(self.completed_len, .release);
        return job;
    }

    pub fn stop(self: *Supervisor) void {
        self.mutex.lockUncancelable(self.io);
        self.stopping = true;
        self.condition.broadcast(self.io);
        self.mutex.unlock(self.io);
    }

    pub fn deinit(self: *Supervisor) void {
        self.stop();
        for (self.threads) |thread| if (thread) |owned| owned.join();
        std.debug.assert(self.outstanding == 0);
        self.allocator.destroy(self);
    }

    fn worker(self: *Supervisor, lane: Lane) void {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            var selected: ?usize = null;
            while (selected == null) {
                for (self.queue[0..self.queue_len], 0..) |job, index| if (job.?.lane == lane) {
                    selected = index;
                    break;
                };
                if (selected != null) break;
                if (self.stopping) {
                    self.mutex.unlock(self.io);
                    return;
                }
                self.condition.waitUncancelable(self.io, &self.mutex);
            }
            const index = selected.?;
            const job = self.queue[index].?;
            for (index..self.queue_len - 1) |position| self.queue[position] = self.queue[position + 1];
            self.queue_len -= 1;
            self.queue[self.queue_len] = null;
            const canceled_before_io = self.stopping;
            self.mutex.unlock(self.io);
            job.run(job.context, canceled_before_io);
            self.mutex.lockUncancelable(self.io);
            // Outstanding admission includes ready and running jobs. A worker
            // always owns its completion slot before issuing native I/O.
            std.debug.assert(self.completed_len < capacity);
            self.completed[(self.completed_head + self.completed_len) % capacity] = job;
            self.completed_len += 1;
            self.ready.store(self.completed_len, .release);
            self.mutex.unlock(self.io);
            self.wake.signal(self.wake.context);
        }
    }
};
