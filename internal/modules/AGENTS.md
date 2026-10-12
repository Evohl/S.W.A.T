# Module Registry

## Purpose

- Own the central Arch module catalog, selected-profile state, dependency plans, and installed/service readiness projection.

## Ownership

- `catalog.go`: immutable profile IDs, descriptions, package dependencies, service units, and configuration readiness notes
- `state.go`: versioned `modules.json` persistence
- `inspect.go`: read-only Arch package and systemd status inspection

## Local Contracts

- Module IDs and package names are compiled allowlists; request data may contain only module IDs.
- The required `network` profile is always selected and cannot be removed.
- Optional dependencies such as Redis are informational unless marked required.
- A profile is ready only when selected and every required package is installed.
- Module deselection never removes packages or stops/disables services.
- Service units with `ConfigurationRequired` remain stopped until their own validated apply path is implemented.
- Persisted selection is versioned and mode `0600`.

## Work Guidance

- Add package/service dependencies and user-facing purpose text in one catalog entry; keep the module-selection UI driven by this registry.
- Keep inspection read-only and batch system queries; inject the command runner in tests.

## Verification

- `go test ./internal/modules`

## Child DOX Index

- None