# M9.2 multi-listener hosted service

## Design intent

The control ABI was intentionally designed with listener ownership and hosted-service ownership as separate concepts.

`SERVICE_START` consumes a listener handle supplied in `request.handle`, while returning a service handle that identifies the hosted forwarding service. The listener handle is therefore not the service identity. This separation is deliberate: one hosted tcpcc instance, one TUN data path, and one bridge dispatcher can own multiple public listeners while presenting one aggregate service lifecycle to the host.

The original single-listener `service.c` implementation was an incomplete implementation of that model, not a constraint of the ABI and not an accidental path to multi-listener support.

## Runtime model

A hosted service has exactly one service manager and one service worker. Each successful `SERVICE_START` adds a listener entry containing:

- the transferred listening socket;
- that listener's backend IPv4 address and port;
- the saved socket readiness callback state; and
- membership state for the service-wide ready queue.

All listener entries feed the same admission loop and the same bridge dispatcher. Adding listeners must not create one worker, one vCPU, or one dispatcher per listener.

The service handle remains `TCPCC_SERVICE_HANDLE`. Repeated successful `SERVICE_START` requests return that same aggregate handle.

## Ready scheduling and fairness

Listener admission is event-driven. The service worker does not periodically scan the listener list and does not search all listeners on each wakeup.

Each listener owns a separate ready-queue node. Its `sk_data_ready` callback enqueues that listener at most once on the service-wide FIFO ready queue and completes the existing service work completion. Queue membership is protected by a spinlock because the callback can run from socket/BH context; the long-lived service mutex is not taken from that callback.

The worker consumes listeners from the head of the queue. One successful nonblocking `accept` requeues that listener at the tail because more backlog may remain. This gives another ready listener a turn before the same listener is probed again. If the next probe returns `-EAGAIN`, the listener stays off the queue until a later readiness callback. A callback racing with the worker can enqueue the listener, but the membership flag prevents duplicate queue entries.

`accept_batch` remains the total service-wide accepted-connection budget for one worker round. If the budget is exhausted while listeners remain ready, the worker reschedules itself. If the aggregate `max_connections` policy is full, ready listeners remain queued until a bridge-completion notification wakes the worker and admission capacity becomes available again.

Drain, stop, first-listener rollback, listener rollback, and service failure must invalidate ready-queue membership before listener storage can be released. Consequently queue nodes never outlive their listener entries.

This FIFO is a scheduling policy, not a per-listener connection quota. It provides bounded round-robin opportunity among listeners that are simultaneously ready while preserving the single aggregate admission policy.

## Policy scope

`max_connections` and `accept_batch` are service-wide policy. They are established by the first listener and must match on later `SERVICE_START` requests. Consequently, adding N listeners does not multiply the configured connection ceiling by N.

`backend_ipv4` and `backend_port` are listener-local forwarding targets. An accepted public connection must be bridged to the backend stored on the listener that accepted it.

## Ownership and failure rules

A successful `SERVICE_START` transfers ownership of the listener socket to the service. A failed `SERVICE_START` must leave ownership with the control handle so that the caller can close or retry it.

The first listener also creates the aggregate runtime. If first-listener setup fails, listener-list membership, readiness state, callback registration, bridge-completion notifier state, and manager allocation must all roll back.

A later listener failure must roll back only that listener; it must not disturb listeners already owned by the running service.

## Aggregate lifecycle

`SERVICE_STATS`, `SERVICE_DRAIN`, and `SERVICE_STOP` operate on the aggregate service, not on one listener.

- `SERVICE_STATS` reports totals across all listeners and all bridges owned by the service.
- `SERVICE_DRAIN` stops admission on every listener, clears admission readiness, and waits for aggregate active connections to drain.
- `SERVICE_STOP` stops every listener, cancels/reaps the remaining bridges as required, releases every listener socket, and tears down the single worker/notifier pair.

Single-listener behavior remains a compatibility case of this model. Existing single-listener lifecycle markers and service semantics must remain unchanged.

## Capability advertisement

A host must only rely on repeated `SERVICE_START` after `HELLO` advertises `TCPCC_CONTROL_FEATURE_MULTI_LISTENER`. This extends the version-1 capability bitmap; it does not require a control ABI version bump because existing request/response structures and the service handle model are unchanged.

The capability bit is part of the contract, not merely documentation. A regression must read `HELLO` and reject a hosted image that implements repeated `SERVICE_START` but fails to advertise the bit, or advertises the bit without the multi-listener regression succeeding.

## Validation requirements

The hosted regression for this capability must exercise at least two public listeners mapped to two distinct loopback backend ports in one kernel process. It must prove that traffic does not cross-route between backends, that both starts return the same service handle, that statistics are aggregate, and that one drain/stop lifecycle covers both listeners.

The regression should keep both bridges active concurrently so a singleton backend/configuration bug cannot pass accidentally. Existing single-listener service, bridge cancellation/reset isolation, capacity, clean-shutdown, memory, and CPU regressions remain compatibility gates for this change.