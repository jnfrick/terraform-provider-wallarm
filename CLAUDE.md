# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build
```sh
make build       # Build binary locally (terraform-provider-wallarm_vX.Y.Z)
make install     # Build and install to $GOPATH/bin
make init-plugin # Build, copy to Terraform plugin dir, and run terraform init
```

### Testing
```sh
make test        # Unit tests (30s timeout, parallel, race detection)
make testacc     # Acceptance tests against live Wallarm API (120m timeout)

# Run a single test
go test ./wallarm/ -run TestFunctionName -v -timeout 30s

# Run a single acceptance test (requires env vars)
TF_ACC=1 WALLARM_API_HOST=https://api.wallarm.com WALLARM_API_TOKEN=<token> \
  go test ./wallarm/ -run TestAccWallarm<ResourceName> -v -timeout 120m
```

Acceptance tests require:
- `WALLARM_API_HOST` (e.g., `https://api.wallarm.com`, `https://us1.api.wallarm.com`)
- `WALLARM_API_TOKEN` (64-character Base64 API token)

### Linting & Formatting
```sh
make lint        # Run golangci-lint (installs it first)
make fmt         # Format Go files with gofmt
make fmtcheck    # Check formatting without modifying (used in CI pre-build)
make vet         # Run go vet
```

## Architecture

### Package Structure
- **`main.go`**: Entry point; serves the provider via `terraform-plugin-sdk/plugin`.
- **`wallarm/`**: All provider code (single Go package `wallarm`).
  - `provider.go`: Registers all resources and data sources; configures the API client.
  - `config.go`: `Config` struct and `Client()` factory wrapping `github.com/wallarm/wallarm-go`.
  - `default.go`: Shared schema definitions reused across rule resources (`commonResourceRuleFields`, `defaultResourceRuleActionSchema`, `thresholdSchema`, `reactionSchema`, etc.).
  - `utils.go`: Shared helpers for action/hint lookup, ID construction, and state comparison.
  - `resource_<name>.go`: One file per resource with CRUD functions.
  - `resource_<name>_test.go`: Acceptance tests for the corresponding resource.
- **`wallarm/common/`**: Sub-packages shared across resource files.
  - `resourcerule/resource_rule.go`: `ResourceRuleWallarmRead` — centralized Read logic for all `wallarm_rule_*` resources, populating state from the API response.
  - `common/mapper/apitotf/`: Converters from Wallarm API response structs → Terraform state.
  - `common/mapper/tftoapi/`: Converters from Terraform state → Wallarm API request structs.
  - `common/const.go`: Shared constants and `ReadOption`/`CreateOption` types used to vary rule read/create behavior.
- **`version/`**: Single `ProviderVersion` variable injected via ldflags during release.

### Rule Resources Pattern
All `wallarm_rule_*` resources follow the same pattern:
1. **Schema**: Combines resource-specific fields with `commonResourceRuleFields` (from `default.go`) via `lo.Assign(fields, commonResourceRuleFields)`.
2. **`action` block**: The `defaultResourceRuleActionSchema` defines request-matching conditions (header, method, path, URI, etc.) that scope where a rule applies.
3. **Create**: Calls `existsAction()` to detect pre-existing duplicates, then posts to the Wallarm Hints API.
4. **Read**: Delegates to `resourcerule.ResourceRuleWallarmRead()` with `ReadOption` flags to control which fields are populated.
5. **ID format**: Composite string `"<clientID>/<actionID>/<ruleID>/<ruleType>"`.
6. **Import**: All rules support `terraform import` using the composite ID format.

### API Client
The provider wraps `github.com/wallarm/wallarm-go`. Authentication uses `X-WallarmAPI-Token` header (preferred) or the deprecated `X-WallarmAPI-UUID` + `X-WallarmAPI-Secret` pair. The global `ClientID` variable in `config.go` is set once during provider configuration from the `client_id` attribute or by calling `UserDetails()`.

### IP List Resources
`wallarm_denylist`, `wallarm_allowlist`, and `wallarm_graylist` are thin wrappers around `resource_ip_list.go` — they call through to a shared implementation.

### Provider Configuration Environment Variables
| Variable | Default | Description |
|---|---|---|
| `WALLARM_API_TOKEN` | — | API token (preferred auth) |
| `WALLARM_API_HOST` | `https://api.wallarm.com` | API endpoint |
| `WALLARM_API_CLIENT_ID` | — | Tenant/client ID override |
| `WALLARM_API_RETRIES` | 3 | Retry count |
