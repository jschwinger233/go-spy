# go-spy

Dump goroutines from a running process.

# Usage

```
$ sudo go-spy $(pidof containerd)

...
-- Goroutine 16: waiting
  0x5569d73833f6 runtime.gopark+214
  0x5569d73b3317 time.Sleep+311
  0x5569d7b85b7f github.com/containerd/containerd/runtime/restart/monitor.(*monitor).run+63
  0x5569d7b846ca github.com/containerd/containerd/runtime/restart/monitor.init.0.func1.1+42
  0x5569d73b6781 runtime.goexit+1
-- Goroutine 26: waiting
  0x5569d73833f6 runtime.gopark+214
  0x5569d7393d1c runtime.selectgo+1980
  0x5569d7c077d6 github.com/containerd/containerd/services/events.(*service).Subscribe+310
  0x5569d7a56930 github.com/containerd/containerd/api/services/events/v1._Events_Subscribe_Handler+208
  0x5569d85cfb5a github.com/containerd/containerd/services/server.streamNamespaceInterceptor+250
  0x5569d85c697a github.com/grpc-ecosystem/go-grpc-middleware.ChainStreamServer.func1.1.1+58
  0x5569d85c9429 github.com/grpc-ecosystem/go-grpc-prometheus.(*ServerMetrics).StreamServerInterceptor.func1+265
  0x5569d85c697a github.com/grpc-ecosystem/go-grpc-middleware.ChainStreamServer.func1.1.1+58
  0x5569d85cdfb3 go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc.StreamServerInterceptor.func1+1651
  0x5569d85c697a github.com/grpc-ecosystem/go-grpc-middleware.ChainStreamServer.func1.1.1+58
  0x5569d85c681e github.com/grpc-ecosystem/go-grpc-middleware.ChainStreamServer.func1+190
  0x5569d7a012e6 google.golang.org/grpc.(*Server).processStreamingRPC+4550
  0x5569d7a02c85 google.golang.org/grpc.(*Server).handleStream+2533
  0x5569d79fb678 google.golang.org/grpc.(*Server).serveStreams.func1.2+152
  0x5569d73b6781 runtime.goexit+1
...
```

No limitation for the binary:

```
$ sudo file -L $(which containerd)
/usr/bin/containerd: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0c71c3183f9c22b27edfdb71ebcdc3735eea9228, for GNU/Linux 3.2.0, stripped
```

# Known issues

1. Bad optimization may lead to OOM if binary and/or memory usage is big.
2. Memory peeking may fail when goroutines are spawned frequently.
3. Multi-version support is bad and not tested at all. Go1.18 ~ 1.21 should be working, but no guarantee either.
