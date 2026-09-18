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
