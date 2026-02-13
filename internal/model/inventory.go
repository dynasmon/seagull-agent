package model

import "time"

type PackageEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

type InventorySnapshot struct {
	SchemaVersion int                    `json:"schema_version"`
	CollectedAt   *time.Time             `json:"collected_at,omitempty"`
	OS            map[string]interface{} `json:"os"`
	Packages      []PackageEntry         `json:"packages"`
	PackagesHash  string                 `json:"packages_hash,omitempty"`
	PackagesCount int                    `json:"packages_count,omitempty"`
	Manager       string                 `json:"manager,omitempty"`
	Extra         map[string]interface{} `json:"extra"`
}
