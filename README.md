# wprof

## About

Wprof is a low-overhead BPF-based tracer and profiler with the focus
on holistic system-level performance data capture and analysis. It
employs powerful and flexible model of split data capture vs
analysis/visualization phases, which allows to iterate on captured
performance data with exactly the same original data. Wprof generates
Perfetto-based traces and provides many options for filtering and
narrowing down exact subset of data to be visualized.

## Building wprof

```shell
$ sudo dnf -y install elfutils-devel zlib-devel
$ # if you don't have Rust toolchain installed just yet
$ # curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ git clone https://github.com/anakryiko/wprof.git
$ git submodule update --init --recursive
$ cd wprof/src
$ make -j$(nproc)
```

## Using wprof

Start with:

```
$ sudo ./wprof -d1000 -T trace.pb
```

You'll end up with 1 (one) second trace data stored in `wprof.data` and
corresponding Perfetto trace in `trace.pb`. You can reuse that data using
replay mode to modify Perfetto trace parameters. Check `--help` for more
details.

```
$ ./wprof -R -d500 -T trace-500ms.pb
```

For programmatic analysis, emit NDJSON instead of parsing the Perfetto trace,
and inspect the data model with `--json-schema`:

```
$ ./wprof -R -I -D wprof.data          # inspect captured data
$ ./wprof -R -D wprof.data -J trace.json  # JSON output (use -J - for stdout)
$ ./wprof --json-schema               # print the JSON data model and exit
```

## Manual

Reference documentation for individual wprof features: what they do, how to use
them, and their gotchas and implications. New features should be documented here
as they land.

### User-defined tracing (utrace)

wprof supports user-defined probes for capturing custom events alongside
its built-in tracing. Supports uprobes, kprobes, USDT, tracepoints, raw
tracepoints, and BPF program probes with argument capture, stack traces,
and name formatting.

See [UTRACE.md](UTRACE.md) for full documentation.

### Time-delayed capture: `--prepare` and `--activate`

Starting a capture has two phases, and these flags let you control *when* each
happens independently:

- `--prepare <when>` — when to set everything up (load BPF, attach probes,
  inject into target processes). Defaults to immediately at startup.
- `--activate <when>` — when to open the session window and stamp `t=0` (the
  point recording actually begins). Defaults to right after preparation finishes.

> **Overhead note:** preparing early is not free, and how cheap it is depends on
> what is traced. Once prepared, the tracing machinery is live. For BPF and the
> Python/PyTorch trace callbacks, each pre-activation event just hits a
> session-window check and returns without recording, so the per-event cost is
> much smaller than during active collection. CUPTI is partly an exception: once
> subscribed (at prepare) it keeps filling its activity buffers in the background
> regardless, so that part of the cost isn't avoided — but wprof still discards
> those buffers without copying or writing them, so it stays cheaper than active
> collection. For **minimum overhead**, delay `--prepare` so activation follows
> it immediately; for **precise activation timing**, prepare ahead of time and
> accept the extra overhead until activation.

`<when>` is a time spec, resolved against the local clock:

| Spec          | Meaning |
|---------------|---------|
| `@now`        | immediately |
| `@<ISO time>` | absolute local wall-clock time (e.g. `@14:30`, `@14:30:05`, `@2026-06-10T14:30:00`); date-only means midnight, time-only means today |
| `+<dur>`      | offset from wprof start (`+30s`, `+5m`, `+1h`) |
| `/<dur>`      | align to the next epoch-aligned period boundary (`/10s`, `/1m`) |

```
$ sudo ./wprof --activate +30s -d 5s -T trace.pb     # set up now, record 5s starting 30s from now
$ sudo ./wprof --activate @14:30:00 -d 10s -T t.pb   # start recording at 14:30 local time
$ sudo ./wprof --prepare +1s --activate /10s -d 5s   # prep at +1s, start on the next round 10s boundary
```

**Gotchas and implications**

- **Preparation is the expensive part; activation is cheap.** Doing setup ahead
  of time means recording starts with minimal latency at the activation instant,
  which is useful for hitting a precise moment or starting many hosts together.
- **Aligning multiple machines.** `/<dur>` is epoch-referenced, so hosts with
  synchronized clocks that all pass e.g. `--activate /10s` begin recording at the
  same wall-clock instant without having to agree on an exact timestamp.
- **No ring buffer pressure during the lead time.** Pre-activation events are
  dropped in-kernel, so even a long lead time consumes no ring buffer space (some
  tracing overhead is still paid, though — see the overhead note above).
- **`@<ISO time>` is local time**, including DST. A bare time-of-day is *today*;
  if it has already passed, that is an error (wprof does not roll to tomorrow).
- **Errors fail fast.** Where it can tell up front, wprof rejects a `--prepare`
  or `--activate` time in the past, or an `--activate` earlier than `--prepare`,
  before doing any setup. If `--activate` slips into the past *during* preparation
  (prep took longer than the lead time), the capture bails out cleanly.
- **Injected tracees stay alive.** When tracing CUDA/Python targets, the injected
  agent's safety auto-retract timeout is sized to span the whole
  prepare→session-end window, so a long `--activate` delay won't make tracees
  detach mid-session.
- **`-d` is measured from activation.** `t=0` is the activation instant and the
  session runs for the requested duration from there. A `Ctrl-C` before the
  duration elapses clamps the recorded window to the interrupt point.
- **While waiting**, wprof prints `Pending preparation trigger...` /
  `Pending activation trigger...` so you can see which phase it is blocked on.
- **The specs are recorded.** The raw `--prepare`/`--activate` strings are saved
  into `wprof.data` and shown by `wprof -R -I` and in JSON output, so a capture
  is self-describing.
