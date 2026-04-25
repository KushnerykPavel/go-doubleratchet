# Contributing

## Requirements

- Go 1.23+
- `golangci-lint` v2

## Development

```bash
go test ./...          # run all tests
golangci-lint run ./... # run linter
```

## Pull Requests

- One logical change per PR.
- All tests must pass: `go test ./...`
- Zero linter issues: `golangci-lint run ./...`
- New behaviour needs tests. Cryptographic changes need known-answer tests.
- Keep `Close()` calls and key-zeroing patterns consistent with existing code (§8.1).

## Cryptographic Changes

Changes to the ratchet state machine, KDF construction, or AEAD must reference the relevant section of the [Signal Double Ratchet spec](https://signal.org/docs/specifications/doubleratchet/). Include a comment citing the spec section.

## Reporting Bugs

For security vulnerabilities, see [SECURITY.md](SECURITY.md). For other bugs, open a GitHub issue.
