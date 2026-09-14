# M9.2 multi-listener hosted service

## Design intent

The control ABI was intentionally designed with listener ownership and hosted-service ownership as separate concepts.

`SERVICE_START` consumes a listener handle supplied in `request.handle`, while returning a service handle that identifies the hosted forwarding service. The listener handle is therefore not the service identity. This separation is deliberate: one hosted tcpcc instance, one TUN data path, and one bridge dispatcher can own multiple public listeners while presenting one aggregate service lifecycle to the host.

The original single-listener `service.c` implementation was an incomplete implementation of that model, not a constraint of the ABI and not an accidental path to multi-listener support.

## Runtime model

A hosted service has exactly one service manager and one service worker. Each successful `SERVICE_START` adds a listener entry containing:

- the transferred listening socket;
- that listener's backend IPv4 address and port;
- the saved socket readiness callback state;
- listener-local readiness state.

All listener entries feed the same admission loop and the same bridge dispatcher. Adding listeners must not create one worker, one vCPU, or one dispatcher per listener.

The service handle remains `TCPCC_SERVICE_HANDLE`. Repeated successful `SERVICE_START` requests return that same aggregate handle.

## Policy scope

`max_connections` and `accept_batch` are service-wide policy. They are established by the first listener and must match on later `SERVICE_START` requests. Consequently, adding N listeners does not multiply the configured connection ceiling by N.

`backend_ipv4` and `backend_port` are listener-local forwarding targets. An accepted public connection must be bridged to the backend stored on the listener that accepted it.

## Ownership and failure rules

A successful `SERVICE_START` transfers ownership of the listener socket to the service. A failed `SERVICE_START` must leave ownership with the control handle so that the caller can close or retry it.

The first listener also creates the aggregate runtime. If first-listener setup fails, callback registration, bridge-completion notifier state, and manager allocation must all roll back.

A later listener failure must roll back only that listener; it must not disturb listeners already owned by the running service.

## Aggregate lifecycle

`SERVICE_STATS`, `SERVICE_DRAIN`, and `SERVICE_STOP` operate on the aggregate service, not on one listener.

- `SERVICE_STATS` reports totals across all listeners and all bridges owned by the service.
- `SERVICE_DRAIN` stops admission on every listener and waits for aggregate active connections to drain.
- `SERVICE_STOP` stops every listener, cancels/reaps the remaining bridges as required, releases every listener socket, and tears down the single worker/notifier pair.

Single-listener behavior remains a compatibility case of this model. Existing single-listener lifecycle markers and service semantics must remain unchanged.

## Capability advertisement

A host must only rely on repeated `SERVICE_START` after `HELLO` advertises `TCPCC_CONTROL_FEATURE_MULTI_LISTENER`. This extends the version-1 capability bitmap; it does not require a control ABI version bump because existing request/response structures and the service handle model are unchanged.

## Validation requirements

The hosted regression for this capability must exercise at least two public listeners mapped to two distinct loopback backend ports in one kernel process. It must prove that traffic does not cross-route between backends, that both starts return the same service handle, that statistics are aggregate, and that one drain/stop lifecycle covers both listeners.