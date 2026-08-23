# Kernel patch policy

This directory contains the complete `linux-tcp-cc` delta applied to the pinned upstream Linux tree.

`series` is authoritative. Non-comment entries are repository-relative patch paths and are applied in order by `scripts/prepare-linux.sh`.

Patches should be limited to the userspace architecture/runtime integration, project netdevice integration, and narrowly justified generic hooks. Congestion-control semantics are upstream-owned.

Protected files recorded in `upstream/protected.sha256` must remain byte-identical to the pinned upstream revision unless a dedicated design review explicitly adds a path to `upstream/protected-allowlist.txt`.
