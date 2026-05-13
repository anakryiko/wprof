# utrace: User-Defined Tracing

wprof supports augmenting its built-in scheduler/IRQ/timer tracing with
user-defined event sources. These produce either **instant events** (single
point-in-time) or **spans** (entry/exit pairs rendered as Perfetto slices).

Define probes with `-U '<definition>'` on the command line, or put multiple
definitions in a file (one per line, `#` for comments) and pass
`-U @filepath`.

## Quick examples

```bash
# trace a user function, capture first two args
wprof -U 'u:process_request (arg:0:u32->id, arg:1:str->name, pid:1234)'

# trace a kernel function with all args from BTF
wprof -U 'k:vfs_write (arg:*)'

# trace sched_switch tracepoint, pick specific fields by name
wprof -U 'tp:sched:sched_switch (arg:prev_comm, arg:next_comm, arg:prev_pid)'

# USDT probe with string arg
wprof -U 'usdt:myapp:request_start (arg:0:s32, arg:1:str, path:./myapp, pid:1234)'

# raw tracepoint with name template
wprof -U 'raw_tp:sys_enter (arg:id) | name:"syscall #{id}" |'

# function span (entry + exit as a Perfetto slice)
wprof -U 'uspan:do_work (arg:0->task_id, arg:ret->result, pid:1234, path:./worker)'

# generic span from two different probes
wprof -U 'usdt:app:req_start (arg:0) ~~ usdt:app:req_end (arg:0)'

# multiple probes from a config file
wprof -U @probes.utrace

# auto resolve pid via nvidia-smi
wprof -U 'usdt:myapp:request_start (arg:0, pid:nvidia-smi)'
```

## Probe types

### Instant probes

| Prefix    | Target spec          | Description                          |
|-----------|----------------------|--------------------------------------|
| `u:`      | `func_name[+offset]` | Userspace function entry (uprobe)    |
| `uret:`   | `func_name`          | Userspace function return (uretprobe)|
| `usdt:`   | `provider:name`      | User Statically-Defined Tracepoint   |
| `k:`      | `func_name[+offset]` | Kernel function entry (kprobe)       |
| `kret:`   | `func_name`          | Kernel function return (kretprobe)   |
| `tp:`     | `category:name`      | Classic kernel tracepoint            |
| `raw_tp:` | `name`               | Raw kernel tracepoint (BTF-based)    |
| `bpf:`    | `prog_name`          | Loaded BPF program entry (fentry)    |
| `bpfret:` | `prog_name`          | Loaded BPF program return (fexit)    |

### Span probes (entry + exit pairs)

| Prefix      | Description                          |
|-------------|--------------------------------------|
| `uspan:`    | Uprobe + uretprobe on same function  |
| `kspan:`    | Kprobe + kretprobe on same function  |
| `bpfspan:`  | BPF fentry + fexit on same function  |

### Generic spans

Combine any two non-span probes with `~~` to form a span:

```
<entry_probe> (<params>) ~~ <exit_probe> (<params>)
```

Settings (`| ... |`) apply to the span as a whole.

## Parameters

Parameters go inside `(...)` after the target spec, comma-separated.

### Argument capture

wprof can capture function arguments and return values from probes.
Captured values are emitted as annotations in Perfetto traces and as
key-value pairs in JSON output, and can be used in `name:` templates
to dynamically label events and spans.

```
arg:<index-or-name>[:<type>][->display_name]
```

**By index:** `arg:0`, `arg:1`, ..., `arg:ret`

**By name:** `arg:prev_pid`, `arg:filename`, `arg:id` (resolved from BTF
or tracepoint format metadata).

**Wildcard:** `arg:*` captures all available arguments with auto-detected
types and names.

**Supported types:**

| Type  | Aliases | Description                |
|-------|---------|----------------------------|
| `u8`  |         | Unsigned 8-bit             |
| `u16` |         | Unsigned 16-bit            |
| `u32` |         | Unsigned 32-bit            |
| `u64` |         | Unsigned 64-bit (default)  |
| `s8`  |         | Signed 8-bit               |
| `s16` |         | Signed 16-bit              |
| `s32` | `int`   | Signed 32-bit              |
| `s64` | `long`  | Signed 64-bit              |
| `str` |         | Null-terminated C string   |
| `ptr` |         | Pointer (displayed as hex) |

When type is omitted, wprof infers it from BTF (for kprobes, raw
tracepoints, BPF probes) or from the tracefs format file (for classic
tracepoints) or from ELF USDT note metadata (for USDTs). Falls back to
`u64` if no metadata is available.

**Rules:**
- Return probes (`uret:`, `kret:`, `bpfret:`) only support `arg:ret`
- `arg:ret` is only valid on return and span probes
- `arg:*` cannot be combined with other arg specs

### Stack trace capture

`stack` (aliases: `st`, `stacktrace`)

Captures the call stack when the probe fires. Enable stack output with
`-S utrace` or `--stacks utrace`.

### Process/binary filters (uprobe and USDT only)

- `pid:<PID>` -- attach only to the given process; wprof scans its loaded
  binaries to find the target symbol/USDT
- `path:<path>` -- attach to a specific binary
- Both can be combined: `path:` identifies the binary, `pid:` scopes to
  the process

For generic spans with USDT, `path:`/`pid:` on the first probe are
inherited by the second.

#### Auto-discovery (USDT only)

- `pid:nvidia-smi` -- attach to every GPU process reported by
  `nvidia-smi --query-compute-apps=pid`. The cfg is expanded at setup
  time into one concrete attachment per discovered PID; PIDs that don't
  expose the requested USDT are skipped with a warning. Setup fails only
  if no discovered PID exposes the USDT. Example:

  ```
  wprof -U 'usdt:myapp:request_start (arg:0, pid:nvidia-smi)'
  ```

## Settings

Settings go inside `| ... |` after the parameters, comma-separated.

### Custom probe ID

`id:<identifier>` or `id:'identifier with spaces'`

Sets a custom string identifier for the probe, used as `utrace_id` in
JSON output instead of the default numeric index. Multiple probes
sharing the same ID will have their events combined on the same
per-thread track in Perfetto (see **Perfetto rendering** below).

### Name format template

`name:<template>` or `name:'template with spaces'`

Customizes event names with `{...}` argument placeholders. See
**Perfetto rendering** below for details and examples.

## Perfetto rendering

Utrace events are captured in the context of the thread that was active
when the probe fired. In Perfetto, each utrace probe gets a separate
child track under the thread's scheduler track. The track is named after
the probe target (e.g., `sched_switch`) or the custom `id:` setting.

**Track grouping:** If multiple probes (whether instants, spans, or a
mix) share the same `id:` value, all their events are rendered on the
same per-thread child track. This is useful for grouping related probes:

```bash
# these two probes share a track per thread
-U 'k:mutex_lock (arg:*) | id:locks |'
-U 'k:mutex_unlock (arg:*) | id:locks |'
```

**Span rendering:** Span probes (`uspan:`, `kspan:`, `bpfspan:`, and
generic `~~` spans) produce Perfetto slices. The entry event starts the
slice and the matching exit event ends it.

**Event names:** By default, each event is labeled with the probe's
target name (e.g., `process_request`, `sched_switch`). Use the `name:`
setting to customize this with argument substitution:

```bash
# each event shows the actual syscall number
-U 'raw_tp:sys_enter (arg:id) | name:"syscall #{id}" |'

# each span shows the request ID
-U 'uspan:handle_request (arg:0->req_id) | name:"request {req_id}" |'
```

Placeholders use `{...}` syntax and can reference arguments by their
positional name (`{arg0}`) or by their display name (`{req_id}`,
`{prev_comm}`). Both forms work if the argument has a name. Captured
argument values also appear as annotations on the Perfetto slice or
instant event.

## JSON output

With `-J`, utrace events appear as:

```json
{
  "ts": 0.001234,
  "t": "utrace_instant",
  "task": {"tid": 1234, "pid": 5678, "comm": "myapp", "pcomm": "myapp"},
  "cpu": 3,
  "utrace_id": "my_probe",
  "name": "syscall #1",
  "args": {"id": 1, "filename": "/etc/hosts"}
}
```

Event types: `utrace_instant`, `utrace_entry`, `utrace_exit`.

Argument values are formatted by type: integers as decimal, pointers as
`"0x..."` hex strings, strings as JSON strings.

## Type inference

wprof automatically detects argument types and names when metadata is
available:

- **kprobes / BPF probes**: from kernel or program BTF
- **raw tracepoints**: from `__bpf_trace_<name>` BTF function prototype
- **classic tracepoints**: from `/sys/kernel/debug/tracing/events/<cat>/<name>/format`
- **USDTs**: arg count and sizes from `.note.stapsdt` ELF section

Use `arg:*` to capture all detected arguments with their inferred types
and names.
```
