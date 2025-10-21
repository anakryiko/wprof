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




