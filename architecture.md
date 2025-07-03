# Architecture

This is a learning exercise - I wanted to see how much performance I could squeeze out of a single-threaded IEEE 2030.5 proxy written in Zig. Coming from writing production proxies with Pingora (which makes everything easy with its sophisticated toolkit), I was curious about building something minimal (and hopefully elegant) from scratch.

## Why Single-Threaded?

Small is beautiful. Instead of the usual multi-threaded complexity, I wanted to explore the limits of a single event loop. No synchronization, no locks, no Arc<Mutex<T>> ceremony or trait soup - just straightforward async I/O.

## Core Design

The entire proxy runs on one libuv event loop:

```
Client Device → [mTLS] → Event Loop → [HTTP Pool] → Backend
```

Everything is async, nothing blocks. The only "thread" is a work queue for logging so we don't stall the main loop writing to disk.

## Memory Strategy

**Arena Allocators**: Each connection gets an arena. When the connection dies, everything gets freed in one shot.

**Reference Counting**: For stuff that outlives a single callback, I built a simple RefCounted type. No atomics needed since we're single-threaded.

**Zero-Copy XML**: The XML "parser" just scans for the root element name. Returns a slice into the original buffer. Good enough to identify IEEE 2030.5 message types.

## Key Components

### Connection Pool
Instead of creating a new upstream connection for each request, we pool them. Each backend host gets its own pool with:
- Async DNS resolution (cached)
- Health checks
- Automatic sizing

### mTLS Handling
OpenSSL does the heavy lifting. We validate IEEE 2030.5 certificates, extract the LFDI/SFDI, and cache sessions for fast reconnects.

### Backpressure
When we get too many concurrent requests (>500), we stop accepting new connections until things calm down. Prevents meltdown under load.

## libuv for Everything

libuv gives us:
- Async TCP (accept, read, write)
- Async DNS 
- Timers
- Work queue (for logging)

On Linux it uses epoll, not io_uring. Good enough for this experiment.

## What's Not Here

No web framework abstractions. No trait hierarchies. No async runtime magic. Just callbacks and explicit resource management. 

The code is verbose in places, but you can follow the flow from accept() to response without diving through 15 layers of abstraction.

## Performance Notes

On my M1 MacBook, this thing can handle:
- ~10K requests/sec for small payloads
- ~5K mTLS handshakes/sec
- Sub-millisecond latency for cached connections


## Future Experiments

Would be fun to:
- Try io_uring instead of epoll (Tigerbeetle-style)
- Benchmark against a "proper" proxy
- See how far we can push the single-thread model

But honestly, this already does what I wanted - prove you can build a fast, correct proxy without all the usual complexity.

## Lessons Learned

1. Single-threaded goes surprisingly far
2. Arena allocators make memory management trivial
3. You don't need a framework for everything
4. Zero-copy parsing is worth it
5. Connection pooling is essential
6. Zig makes you think about every allocation

## Things to Clean Up

The code has a bunch of `std.atomic.Value` counters that are completely unnecessary since we're single-threaded. They're scattered everywhere - proxy stats, connection pool metrics, observability counters. Pure overhead for no benefit. Should just be regular fields.

The code isn't production-ready (and isn't meant to be), but it's fast, readable, and does the job without ceremony.
