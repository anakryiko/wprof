# wprof JSON Output Schema

wprof's JSON mode (`-J`/`--json-trace`) emits newline-delimited JSON (one JSON object
per line) describing a profiling session. The output consists of three sections
in a fixed order:

1. **Header** — exactly 1 line, session metadata
2. **Stacks** — exactly `stack_cnt` lines (0 if stack traces were not captured)
3. **Events** — remaining lines, time-ordered trace events

## Conventions

- **Timestamps** and **durations** are float seconds (nanosecond precision via
  `%.9lf`). Timestamps are relative to session start (i.e., first event is
  near 0.0).
- **Task objects** represent a thread or process identity. The `tid` field is
  omitted for idle threads (pid 0).
  ```json
  {"tid": 1234, "pid": 1000, "comm": "myapp"}
  ```
- All header fields are always present (no conditional omission) so consumers
  can rely on a fixed schema.
- JSON examples below are shown multi-line for readability; in actual output
  each record is a single compact line.

## Header

The first line contains session metadata. Example:

```json
{
  "version": "2.0",
  "dur": 1.000000000,
  "timer_freq_hz": 997,
  "capture_ipis": false,
  "capture_requests": false,
  "capture_scx": false,
  "capture_cuda": false,
  "capture_pystacks": false,
  "stacks": ["timer", "offcpu"],
  "stack_cnt": 42,
  "event_cnt": 100000,
  "pmus": ["instructions", "cycles", "IPC"]
}
```

| Field              | Type            | Description                                                          |
|--------------------|-----------------|----------------------------------------------------------------------|
| `version`          | string          | Format version (`"major.minor"`)                                     |
| `dur`              | float           | Session duration in seconds                                          |
| `timer_freq_hz`    | int             | On-CPU timer interrupt frequency                                     |
| `capture_ipis`     | bool            | Whether IPI events were captured                                     |
| `capture_requests` | bool            | Whether request tracing was enabled                                  |
| `capture_scx`      | bool            | Whether sched-ext events were captured                               |
| `capture_cuda`     | bool            | Whether CUDA activity was captured                                   |
| `capture_pystacks` | bool            | Whether Python stack traces were captured                            |
| `stacks`           | array of string | Stack trace kinds captured (e.g., `["timer","offcpu"]`, `[]` if none)|
| `stack_cnt`        | int             | Number of stack trace lines that follow (0 if none)                  |
| `event_cnt`        | int             | Total number of event lines that follow                              |
| `pmus`             | array of string | PMU counter names (e.g., `["instructions","cycles"]`, `[]` if none)  |

## Callstacks (stack traces)

Each stack trace line describes a resolved call stack. Example:

```json
{
  "id": 42,
  "frames": [
    "[U] main+0x1a",
    "[U] do_work+0x35",
    "[U] epoll_wait+0x19",
    "[K] entry_SYSCALL_64_after_hwframe+0x4b",
    "[K] do_syscall_64+0x6b",
    "[K] schedule+0x8e"
  ],
  "srcs": [
    "src/main.c:42",
    "src/work.c:118",
    "",
    "",
    "",
    ""
  ]
}
```

| Field    | Type            | Description                                                                                     |
|----------|-----------------|-------------------------------------------------------------------------------------------------|
| `id`     | int             | Stack trace ID, referenced by event fields (`stack_id`, `offcpu_stack_id`, `waker_stack_id`)    |
| `frames` | array of string | Symbolized frame names, outermost caller first (bottom-to-top); user frames precede kernel frames |
| `srcs`   | array of string | *(optional)* Parallel to `frames`; `"path:line"` or `""`. Present when any frame has source info|

### Frame name format

- `[K] func_name+0xNN` — kernel frame with function offset
- `[U] func_name+0xNN` — userspace frame with function offset
- `[Py] func_name` — Python frame (source info in `srcs` array)
- `[U] func_name (inlined)` — inlined frame (no offset)
- `[K] <unknown>` / `[U] <unknown>` — unsymbolized frame

The `+0xNN` offset is omitted when zero.

## Events

Each event line has a `"t"` field identifying the event type, plus common and
type-specific fields.

### Common fields

These fields appear on every event:

| Field  | Type   | Description                                                       |
|--------|--------|-------------------------------------------------------------------|
| `ts`   | float  | Timestamp in seconds relative to session start                    |
| `t`    | string | Event type                                                        |
| `cpu`  | int    | CPU number where the event occurred                               |
| `numa` | int    | *(optional)* NUMA node; present only when `-e numa` is enabled    |

Most events include a `task` object identifying the associated thread. The
`switch` event uses `prev` and `next` instead.

**Timestamp semantics:** For duration-based events (`hardirq`, `softirq`, `wq`,
`ipi`, `scx_dsq`, and CUDA events), `ts` is the **end** timestamp and
`start_ts` marks the beginning. The duration `dur` equals `ts - start_ts`.
For instantaneous events (`switch`, `timer`, `fork`, `exec`, etc.), `ts` is
when the event occurred.

**PMU counters:** When present, the `pmus` array contains hardware performance
counter values accumulated during the event's time span (e.g., instructions
executed during an interrupt handler, or during `prev`'s last on-CPU slice for
`switch` events). Values are parallel to the header's `pmus` name array.

---

### Scheduling events

#### `switch` — context switch

Emitted when a thread is switched off-CPU and another is switched on.

| Field                | Type           | Description                                                                    |
|----------------------|----------------|--------------------------------------------------------------------------------|
| `prev`               | task           | Thread being switched out                                                      |
| `next`               | task           | Thread being switched in                                                       |
| `prev_state`         | string         | `"preempted"` or `"blocked"` — why `prev` went off-CPU                         |
| `prev_prio`          | int            | Scheduling priority of `prev`                                                  |
| `next_prio`          | int            | Scheduling priority of `next`                                                  |
| `waking_ts`          | float          | *(optional)* Timestamp when `next` was woken                                   |
| `waking_reason`      | string         | *(optional)* Why the thread was woken (e.g., `"woken"`)                        |
| `waker`              | task           | *(optional)* Thread that woke `next`                                           |
| `waking_cpu`         | int            | *(optional)* CPU where the waker ran                                           |
| `offcpu_dur`         | float          | *(optional)* How long `next` was off-CPU, in seconds                           |
| `next_state`         | string         | *(optional)* `"preempted"` or `"blocked"` — why `next` was off-CPU previously  |
| `offcpu_stack_id`    | int            | *(optional)* Stack trace ID for the off-CPU stack                              |
| `waker_stack_id`     | int            | *(optional)* Stack trace ID for the waker's stack                              |
| `compound_delay`     | float          | *(optional)* Accumulated wakeup chain delay, in seconds                        |
| `compound_chain_len` | int            | *(optional)* Length of the waker-wakee chain                                   |
| `pmus`               | array of float | *(optional)* PMU counter values, parallel to header `pmus`                     |

```json
{
  "ts": 0.500123456,
  "t": "switch",
  "prev": {"tid": 1234, "pid": 1000, "comm": "worker"},
  "next": {"tid": 5678, "pid": 5000, "comm": "myapp"},
  "cpu": 3,
  "prev_state": "blocked",
  "prev_prio": 120,
  "next_prio": 120,
  "waking_ts": 0.500100000,
  "waking_reason": "woken",
  "waker": {"tid": 9999, "pid": 5000, "comm": "scheduler"},
  "waking_cpu": 7,
  "offcpu_dur": 0.005000000,
  "next_state": "blocked",
  "offcpu_stack_id": 42,
  "waker_stack_id": 99,
  "compound_delay": 0.006500000,
  "compound_chain_len": 3,
  "pmus": [150000.0, 80000.0, 1.875]
}
```

#### `timer` — on-CPU timer sample

Periodic timer interrupt capturing what a thread is doing on-CPU.

| Field      | Type | Description                          |
|------------|------|--------------------------------------|
| `task`     | task | Thread running on-CPU                |
| `stack_id` | int  | Stack trace ID for the on-CPU stack  |

```json
{
  "ts": 0.010012345,
  "t": "timer",
  "task": {"tid": 1234, "pid": 1000, "comm": "myapp"},
  "cpu": 5,
  "stack_id": 17
}
```

---

### Interrupt events

#### `hardirq` — hardware interrupt

| Field      | Type           | Description                                                                |
|------------|----------------|----------------------------------------------------------------------------|
| `task`     | task           | Thread interrupted                                                         |
| `dur`      | float          | Duration of interrupt handling                                             |
| `start_ts` | float          | *(optional)* Start timestamp (omitted if interrupt started before session) |
| `irq`      | int            | IRQ number                                                                 |
| `action`   | string         | IRQ handler name                                                           |
| `pmus`     | array of float | *(optional)* PMU counter values, parallel to header `pmus`                 |

```json
{
  "ts": 0.000234175,
  "t": "hardirq",
  "task": {"pid": 0, "comm": "swapper/187"},
  "dur": 0.000011568,
  "start_ts": 0.000222607,
  "cpu": 187,
  "irq": 193,
  "action": "nvme1q30"
}
```

#### `softirq` — software interrupt

| Field      | Type           | Description                                                |
|------------|----------------|------------------------------------------------------------|
| `task`     | task           | Thread interrupted                                         |
| `dur`      | float          | Duration of softirq handling                               |
| `start_ts` | float          | *(optional)* Start timestamp                               |
| `action`   | string         | Softirq type (e.g., `"rcu"`, `"timer"`, `"net_rx"`)       |
| `pmus`     | array of float | *(optional)* PMU counter values, parallel to header `pmus` |

```json
{
  "ts": 0.000297060,
  "t": "softirq",
  "task": {"pid": 0, "comm": "swapper/253"},
  "dur": 0.000000411,
  "start_ts": 0.000296649,
  "cpu": 253,
  "action": "rcu"
}
```

#### `ipi_send` — inter-processor interrupt sent

| Field        | Type   | Description                                    |
|--------------|--------|------------------------------------------------|
| `task`       | task   | Thread that sent the IPI                       |
| `kind`       | string | IPI kind                                       |
| `target_cpu` | int    | *(optional)* Target CPU (omitted for multicast)|

```json
{
  "ts": 0.100500000,
  "t": "ipi_send",
  "task": {"tid": 1234, "pid": 1000, "comm": "myapp"},
  "cpu": 3,
  "kind": "reschedule",
  "target_cpu": 7
}
```

#### `ipi` — inter-processor interrupt received

| Field        | Type           | Description                                                |
|--------------|----------------|------------------------------------------------------------|
| `task`       | task           | Thread interrupted by the IPI                              |
| `dur`        | float          | Duration of IPI handling                                   |
| `start_ts`   | float          | *(optional)* Start timestamp                               |
| `kind`       | string         | IPI kind                                                   |
| `sender_cpu` | int            | *(optional)* CPU that sent the IPI                         |
| `ipi_delay`  | float          | *(optional)* Delay between send and receive, in seconds    |
| `pmus`       | array of float | *(optional)* PMU counter values, parallel to header `pmus` |

```json
{
  "ts": 0.100501500,
  "t": "ipi",
  "task": {"tid": 5678, "pid": 5000, "comm": "worker"},
  "dur": 0.000000800,
  "start_ts": 0.100500700,
  "cpu": 7,
  "kind": "reschedule",
  "sender_cpu": 3,
  "ipi_delay": 0.000000200
}
```

---

### Workqueue events

#### `wq` — workqueue execution

| Field      | Type           | Description                                                |
|------------|----------------|------------------------------------------------------------|
| `task`     | task           | Worker thread                                              |
| `dur`      | float          | Duration of work item execution                            |
| `start_ts` | float          | *(optional)* Start timestamp                               |
| `desc`     | string         | Work function description                                  |
| `pmus`     | array of float | *(optional)* PMU counter values, parallel to header `pmus` |

```json
{
  "ts": 0.000202497,
  "t": "wq",
  "task": {"tid": 2525993, "pid": 2525993, "comm": "kworker/u1266:1"},
  "dur": 0.000084638,
  "start_ts": 0.000117859,
  "cpu": 187,
  "desc": "btrfs-delalloc"
}
```

---

### Task lifecycle events

#### `fork` — new thread/process created

| Field   | Type | Description          |
|---------|------|----------------------|
| `task`  | task | Parent thread        |
| `child` | task | Newly created thread |

```json
{
  "ts": 0.004985681,
  "t": "fork",
  "task": {"tid": 1318694, "pid": 1318624, "comm": "Collection-7"},
  "child": {"tid": 2688142, "pid": 2688142, "comm": "Collection-7"},
  "cpu": 211
}
```

#### `exec` — process executed a new binary

| Field      | Type   | Description                                     |
|------------|--------|-------------------------------------------------|
| `task`     | task   | Thread that called exec                         |
| `filename` | string | Path of the new executable                      |
| `old_tid`  | int    | *(optional)* Previous TID, if changed by exec   |

```json
{
  "ts": 0.032770664,
  "t": "exec",
  "task": {"tid": 2688142, "pid": 2688142, "comm": "env"},
  "cpu": 133,
  "filename": "/usr/bin/env"
}
```

#### `task_rename` — thread name changed

The `task` object for this event has an extra `old_comm` field with the
previous name, and `comm` contains the new name.

| Field  | Type | Description                                                          |
|--------|------|----------------------------------------------------------------------|
| `task` | task | Thread being renamed; contains both `old_comm` and `comm` (new name) |

```json
{
  "ts": 0.032690002,
  "t": "task_rename",
  "task": {"tid": 2688142, "pid": 2688142, "old_comm": "Collection-7", "comm": "env"},
  "cpu": 133
}
```

#### `task_exit` — thread exiting

| Field  | Type | Description    |
|--------|------|----------------|
| `task` | task | Exiting thread |

```json
{
  "ts": 0.036811976,
  "t": "task_exit",
  "task": {"tid": 2688143, "pid": 2688143, "comm": "check_service_e"},
  "cpu": 75
}
```

#### `task_free` — thread resources freed

| Field  | Type | Description                              |
|--------|------|------------------------------------------|
| `task` | task | Thread whose resources are being freed   |

```json
{
  "ts": 0.062299945,
  "t": "task_free",
  "task": {"tid": 2688143, "pid": 2688143, "comm": "check_service_e"},
  "cpu": 224
}
```

---

### Request tracing events

#### `req_event` — request lifecycle event

| Field      | Type   | Description                                                     |
|------------|--------|-----------------------------------------------------------------|
| `task`     | task   | Thread handling the request                                     |
| `event`    | string | Event type: `"start"`, `"end"`, `"set"`, `"unset"`, `"clear"`  |
| `req_id`   | int    | Request identifier                                              |
| `req_name` | string | Request name                                                    |
| `latency`  | float  | *(optional)* Request latency in seconds (on `"end"` events)     |

```json
{
  "ts": 0.200000000,
  "t": "req_event",
  "task": {"tid": 1234, "pid": 1000, "comm": "server"},
  "cpu": 3,
  "event": "end",
  "req_id": 42,
  "req_name": "HTTP GET /api/data",
  "latency": 0.015300000
}
```

#### `req_task_event` — request task scheduling event

| Field         | Type   | Description                                          |
|---------------|--------|------------------------------------------------------|
| `task`        | task   | Thread involved                                      |
| `event`       | string | Event type: `"enqueue"`, `"dequeue"`, `"stats"`      |
| `req_id`      | int    | Request identifier                                   |
| `req_task_id` | int    | Request task identifier                              |
| `wait_time`   | float  | *(optional)* Time spent waiting, in seconds          |

```json
{
  "ts": 0.200100000,
  "t": "req_task_event",
  "task": {"tid": 1234, "pid": 1000, "comm": "server"},
  "cpu": 3,
  "event": "dequeue",
  "req_id": 42,
  "req_task_id": 100,
  "wait_time": 0.003200000
}
```

---

### Sched-ext events

#### `scx_dsq` — sched-ext dispatch queue event

| Field         | Type   | Description                                    |
|---------------|--------|------------------------------------------------|
| `task`        | task   | Thread being dispatched                        |
| `dur`         | float  | Time spent in the dispatch queue               |
| `start_ts`    | float  | *(optional)* Insertion timestamp               |
| `insert_type` | string | How the task was inserted into the DSQ         |
| `dsq_id`      | int    | Dispatch queue ID                              |
| `layer_id`    | int    | Sched-ext layer ID                             |

```json
{
  "ts": 0.300500000,
  "t": "scx_dsq",
  "task": {"tid": 1234, "pid": 1000, "comm": "worker"},
  "dur": 0.000050000,
  "start_ts": 0.300450000,
  "cpu": 5,
  "insert_type": "dispatch",
  "dsq_id": 1,
  "layer_id": 0
}
```

---

### CUDA host events

#### `cuda_api` — host-side CUDA API call

These events are associated with the calling thread, like any other
thread-level event.

| Field      | Type   | Description                          |
|------------|--------|--------------------------------------|
| `task`     | task   | Thread making the CUDA API call      |
| `dur`      | float  | Duration of the API call             |
| `name`     | string | API function name                    |
| `corr_id`  | int    | Correlation ID (links to GPU events) |
| `stack_id` | int    | *(optional)* Stack trace ID          |

```json
{
  "ts": 1.000200000,
  "t": "cuda_api",
  "task": {"tid": 1234, "pid": 1000, "comm": "trainer"},
  "dur": 0.000050000,
  "cpu": 3,
  "name": "cudaLaunchKernel",
  "corr_id": 500,
  "stack_id": 88
}
```

---

### CUDA GPU events

These events represent activity on the GPU. The `task` object identifies
the host process that owns the GPU context, not a thread running on the CPU.

#### `cuda_kernel` — GPU kernel execution

| Field       | Type         | Description                          |
|-------------|--------------|--------------------------------------|
| `task`      | task         | Host process owning the GPU context  |
| `dur`       | float        | Kernel execution duration            |
| `name`      | string       | Kernel function name (demangled)     |
| `device_id` | int          | GPU device ID                        |
| `stream_id` | int          | CUDA stream ID                       |
| `grid`      | array of int | Grid dimensions `[x, y, z]`          |
| `block`     | array of int | Block dimensions `[x, y, z]`         |
| `corr_id`   | int          | Correlation ID (links to host API)   |

```json
{
  "ts": 1.000250000,
  "t": "cuda_kernel",
  "task": {"tid": 1234, "pid": 1000, "comm": "trainer"},
  "dur": 0.002000000,
  "cpu": 3,
  "name": "volta_sgemm_128x64_nn",
  "device_id": 0,
  "stream_id": 7,
  "grid": [256, 1, 1],
  "block": [128, 1, 1],
  "corr_id": 500
}
```

#### `cuda_memcpy` — GPU memory copy

| Field       | Type   | Description                                  |
|-------------|--------|----------------------------------------------|
| `task`      | task   | Host process owning the GPU context          |
| `dur`       | float  | Transfer duration                            |
| `byte_cnt`  | int    | Bytes transferred                            |
| `kind`      | string | Copy direction (e.g., `"HtoD"`, `"DtoH"`)   |
| `src_kind`  | string | Source memory kind                           |
| `dst_kind`  | string | Destination memory kind                      |
| `device_id` | int    | GPU device ID                                |
| `stream_id` | int    | CUDA stream ID                               |
| `corr_id`   | int    | Correlation ID (links to host API)           |

```json
{
  "ts": 1.005000000,
  "t": "cuda_memcpy",
  "task": {"tid": 1234, "pid": 1000, "comm": "trainer"},
  "dur": 0.000500000,
  "cpu": 3,
  "byte_cnt": 4194304,
  "kind": "HtoD",
  "src_kind": "pageable",
  "dst_kind": "device",
  "device_id": 0,
  "stream_id": 7,
  "corr_id": 501
}
```

#### `cuda_memset` — GPU memory set

| Field       | Type   | Description                          |
|-------------|--------|--------------------------------------|
| `task`      | task   | Host process owning the GPU context  |
| `dur`       | float  | Operation duration                   |
| `byte_cnt`  | int    | Bytes set                            |
| `kind`      | string | Memory kind                          |
| `device_id` | int    | GPU device ID                        |
| `stream_id` | int    | CUDA stream ID                       |
| `corr_id`   | int    | Correlation ID (links to host API)   |

```json
{
  "ts": 1.006000000,
  "t": "cuda_memset",
  "task": {"tid": 1234, "pid": 1000, "comm": "trainer"},
  "dur": 0.000010000,
  "cpu": 3,
  "byte_cnt": 1048576,
  "kind": "device",
  "device_id": 0,
  "stream_id": 7,
  "corr_id": 502
}
```

#### `cuda_sync` — GPU synchronization

| Field       | Type   | Description                          |
|-------------|--------|--------------------------------------|
| `task`      | task   | Host process owning the GPU context  |
| `dur`       | float  | Synchronization duration             |
| `kind`      | string | Synchronization type                 |
| `stream_id` | int    | CUDA stream ID                       |
| `corr_id`   | int    | Correlation ID (links to host API)   |

```json
{
  "ts": 1.010000000,
  "t": "cuda_sync",
  "task": {"tid": 1234, "pid": 1000, "comm": "trainer"},
  "dur": 0.001000000,
  "cpu": 3,
  "kind": "stream",
  "stream_id": 7,
  "corr_id": 503
}
```
