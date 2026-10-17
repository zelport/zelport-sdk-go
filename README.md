# zelport-sdk-go

Shared Go SDK for end-to-end encrypted Zelport relay clients. The public API
follows Go module compatibility rules for the current 0.x release line.

- `protocol`: wire messages, records, identities and validation.
- `secure`: Noise channels, authenticated catalog encryption and key derivation.
- `transport`: WebSocket transport.
- `client`: encrypted catalog, peer streams, session renewal and client lifecycle.

The SDK has no dependency on Zelport Relay or Zelport App and contains no
server-side management functionality.
Preserve admission/E2E secret separation, identity pinning, durable watermarks,
revocation, bounds and session lifecycle. This extraction is not a security audit.

`make check` runs race tests and vet; `make build` compiles packages. Tests needing
a real relay and private client state are preserved by the relay repository's
integration harness, invoked by staging `make check-integration`.
Tagged module versions can be downloaded directly by Go. See Zelport App's
[protocol documentation](https://github.com/zelport/zelport/blob/main/docs/ports-over-relay-v1.md).

Licensed under the [MIT License](LICENSE).
