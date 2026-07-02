// Package inventory manages the authoritative list of software artefacts
// that may be assessed within the CDSCAM Assurance Platform.
package inventory

import "time"

// InventoryItem represents an OCI repository registered in the platform
// inventory. Inventory items belong to a Team and serve as the authoritative
// source of artefacts that may be assessed.
type InventoryItem struct {
	ID            int64
	Name          string
	Description   string
	TeamID        int64
	Registry      string
	PackageURL    string
	PackageName   string
	RepositoryURL string
	Active        bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// InventoryItemWithTeam extends InventoryItem with the name of the owning team,
// used for display in list and detail views.
type InventoryItemWithTeam struct {
	InventoryItem
	TeamName string
}
