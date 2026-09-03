# Contributing to the QuantaSeal Go SDK

## Development setup

```bash
git clone https://github.com/quantaseal/sdk-go.git
cd sdk-go
go mod tidy

# Run tests
go test ./...

# Lint
go vet ./...
```

## Pull request guidelines

- Target the `main` branch
- All tests must pass
- Follow standard Go idioms - `golangci-lint` clean

## Licence

Apache 2.0.
