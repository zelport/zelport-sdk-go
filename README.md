# zelport-sdk-go

Shared Go SDK for end-to-end encrypted Zelport relay clients. The public API
follows Go module compatibility rules. Before v1, minor releases may contain
breaking API changes as permitted for pre-v1 Go modules.

- `protocol`: wire messages, records, identities and validation.
- `secure`: Noise channels, authenticated catalog encryption and key derivation.
- `transport`: WebSocket transport.
- `client`: encrypted catalog, peer streams, session renewal and client lifecycle.

The SDK has no dependency on Zelport Relay or Zelport App and contains no
server-side management functionality.

`make check` runs race tests and vet; `make build` compiles packages. Relay-backed
tests run from the relay repository with `make check-integration`. See Zelport App's
[protocol documentation](https://github.com/zelport/zelport/blob/main/docs/ports-over-relay-v1.md).

Licensed under the [MIT License](LICENSE).
