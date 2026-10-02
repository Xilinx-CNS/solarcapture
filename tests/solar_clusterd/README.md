# cluster_client (ON-17615)

Minimal reference client demonstrating how an application consumes the
functionality provided by `solar_clusterd`, which lives in SolarCapture
(see `docs/solar_cluster.md`). It was removed from Onload as of Onload
9.2.0 -- only older Onload releases bundle their own copy.

Assumes Onload is installed on this host from its source RPM or DEB
package -- that gives you the ef_vi headers/library this client needs
(see Build below). Also assumes `solar_clusterd` is installed and on
`PATH` with its Python extension module already built, from
SolarCapture's own build (or, on an older Onload release that still
bundles it, that identical copy).

## Background

`solar_clusterd` is a daemon that owns a protection domain + vi_set
("cluster") per interface, with capture filters pre-installed from its
config file (see `solar_clusterd`'s `example.conf`). Client applications
attach to a numbered channel within a named cluster and receive matching
packets, without needing their own filter/PD setup.

The client-side handshake lives entirely inside libciul and is
transparent to the calling application:

- `ef_pd_alloc_by_name(&pd, dh, "[idx@]<cluster-name>", flags)` connects to
  the running `solar_clusterd` over its Unix-domain socket, does a version
  handshake, and requests channel `idx` (or any free channel) of the named
  cluster. It falls back to allocating a private PD on a plain interface if
  no cluster of that name exists (e.g. daemon not running).
- `ef_vi_alloc_from_pd(&vi, ...)` then notices the PD came from a cluster
  and transparently allocates the VI from the cluster's existing vi_set
  instead of a fresh one.

`cluster_client.c` is a trimmed-down single-VI RX loop (packet counting,
optional hexdump) built around exactly those two calls, modelled on the
`efsink`/`efrss` sample apps that ship with Onload.

## Build

```sh
make
```

The ef_vi headers (`/usr/include/etherfabric/`) and the static `libciul1.a`
are picked up from their standard installed locations, so no extra `-I`/
`-L` flags are needed. The binary links `libciul1.a` statically -- Onload
deliberately doesn't install `libciul.so` into system library directories
(to avoid an installed copy shadowing whatever version an app was built
against), so static linking is the supported way to build against it.

## Running against solar_clusterd

1. Start `solar_clusterd` using `run_solar_clusterd.sh`, which generates a
   config for you (one cluster, capturing all traffic on the given
   interface):

   ```sh
   sudo ./run_solar_clusterd.sh -i eth4          # cluster "A", 4 channels
   sudo ./run_solar_clusterd.sh -i eth4 -n B -N 8 # cluster "B", 8 channels
   ```

   Run `./run_solar_clusterd.sh -h` for all options, including `-c` to use
   a hand-written config file instead (see solar_clusterd's `example.conf`
   for the full syntax) and `-b` to daemonize instead of running in the
   foreground.

   By default the generated config uses `steal` capture mode (matched
   traffic is diverted from the kernel to the cluster instead of being
   delivered normally -- the same filter type `efsink`/`efrss` use by
   default). Pass `-M sniff` for non-disruptive port mirroring instead, but
   note `ef_filter_spec_set_port_sniff()` is documented (`etherfabric/vi.h`)
   as "not supported by 5000-series and 6000-series adapters" -- on that
   hardware it fails with `EINVAL` (`filter with fields=0x400: failed 22`).

   If `solar_clusterd` isn't installed as a package on this host (e.g.
   you're working against a dev/source SolarCapture checkout instead),
   pass `-t <solarcapture-tree>` to run it straight out of that tree's
   `src/solar_clusterd/`. If the tree doesn't already have
   `cluster_protocol.so` built, this compiles it itself into a cache
   directory next to the script, leaving the tree untouched -- building it
   needs Onload's ef_vi headers and `ciul`/`cplane` static libs, which
   SolarCapture doesn't vendor, so point the `ONLOAD_TREE` env var at a
   built Onload checkout (the same convention `tests/Makefile` and
   `src/unit_tests/Makefile` use), and pass `-p <platform>` too if its
   build directory isn't `build/gnu_$(uname -m)`:

   ```sh
   export ONLOAD_TREE=~/git/onload_internal2
   sudo -E ./run_solar_clusterd.sh -i eth4 -t ~/git/solarcapture
   ```

2. In another shell, run the client against that cluster name (optionally
   with a channel index prefix):

   ```sh
   ./cluster_client 0@A
   # or, to hexdump each packet and stop after 100:
   ./cluster_client -d -n 100 0@A
   ```

   If `EF_VI_CLUSTER_SOCKET` was set to something non-default when
   `solar_clusterd` was started, export the same value before running
   `cluster_client`.

On startup the client prints whether it actually joined the named cluster
or fell back to a plain interface allocation (which happens silently if,
for example, `solar_clusterd` isn't running or the name doesn't match a
configured cluster) -- useful for confirming the daemon handshake worked.
