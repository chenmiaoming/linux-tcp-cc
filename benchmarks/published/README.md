# Published evidence

This directory contains small, reviewable evidence snapshots that may be cited by
the project website or other public documentation.

The snapshots deliberately distinguish two evidence classes:

- `controlled_qualification`: reproducible repository/CI scenarios whose
  parameters and acceptance contract live in this repository.
- `field_observation`: measurements from a real deployment. These preserve
  useful operational evidence, but environmental variance means they must not
  be presented as a controlled performance benchmark.

A field observation may have incomplete commit provenance when the original lab
run did not record an exact source commit. That limitation must be kept in the
snapshot rather than reconstructed later from memory.

Website copy should cite the evidence class and avoid converting a single field
run into an unconditional speedup claim.

## Current snapshots

- `openvz-128m-realhost-2026-09-11.json` — real 128 MiB OpenVZ field observation; useful for deployment/resource evidence, not a controlled speedup benchmark.
- `transoceanic-pr105-2026-08-31.json` — controlled three-repetition native/tcpcc CUBIC/BBR observation on the checked-in 1 Gbit/s, 200 ms RTT, symmetric 10% loss scenario.
- `m10-memory-lifecycle-pr100-2026-08-30.json` — controlled 16,384-flow demand-backed memory lifecycle plus six repeated 8,192-flow post-reclaim stability rounds.
