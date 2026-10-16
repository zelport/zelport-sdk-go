# zelport-sdk-go

Shared Go SDK for encrypted relay clients, extracted from the former Snitzel project. This is a preview API and does not yet promise stable public API compatibility.

- `protocol`: wire messages, records, identities and validation.
- `secure`: Noise channels, authenticated catalog encryption and key derivation.
- `transport`: WebSocket transport.
- `client`: encrypted catalog, peer streams, session renewal and client lifecycle.

The SDK has no dependency on the relay server, gateway or cloud management API.
Preserve admission/E2E secret separation, identity pinning, durable watermarks,
revocation, bounds and session lifecycle. This extraction is not a security audit.

`make check` runs race tests and vet; `make build` compiles packages. Tests needing
a real relay and private client state are preserved by the relay repository's
integration harness, invoked by staging `make check-integration`.
Tagged module versions can be downloaded directly by Go. See the gateway's
[protocol documentation](https://github.com/zelport/zelport/blob/main/docs/ports-over-cloud-v1.md).

Licensed under the [MIT License](LICENSE).
