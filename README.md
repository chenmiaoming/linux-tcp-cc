# linux-tcp-cc

`linux-tcp-cc` is a production-oriented userspace runtime for upstream Linux TCP congestion-control implementations.

The project does **not** reimplement BBR, CUBIC, delivery-rate sampling, TCP loss recovery, or fq pacing. Instead, it aims to run the relevant upstream Linux TCP/networking code with the smallest maintainable userspace architecture/runtime boundary.

## Versioning model

Each supported Linux LTS series has its own long-lived repository branch. The default branch is the newest supported LTS series.

Current branch: `6.18.y`

Current pinned upstream baseline: Linux `v6.18.45` from the kernel.org stable tree.

Patch-level releases inside this branch will follow Linux 6.18.y stable updates after CI and regression validation.

## Maintenance boundary

The long-term maintenance target is to keep project-specific changes concentrated in the userspace architecture, host runtime, packet netdevice, build/configuration, and control/API layers.

The following upstream implementation files are treated as protected source and should remain unmodified:

- `net/ipv4/tcp_bbr.c`
- `net/ipv4/tcp_rate.c`
- Linux TCP recovery core
- `net/sched/sch_fq.c`

Any exception requires an explicit design decision and dedicated review; adapting an LTS release must not silently fork congestion-control semantics.

## Development workflow

Development is milestone-driven. Each independently verifiable task is developed on a topic branch and merged into the corresponding LTS branch through a pull request.

The initial roadmap is tracked in GitHub issues M0 through M8. Early milestones establish upstream provenance, the overlay/build system, and the minimal userspace kernel runtime before enabling BBR performance work.

M8's target product is a TUN-backed inbound server TCP front end, described in
[`docs/m8-server-ingress-design.md`](docs/m8-server-ingress-design.md).

## Fetch the pinned Linux source

```bash
bash ./scripts/fetch-linux.sh
cat .build/upstream.env
cat .build/protected-upstream.sha256
```

The kernel source is fetched into `.deps/linux` and is not vendored into this repository.

## License

GPL-2.0. See `LICENSE`.
