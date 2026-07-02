// Package teams manages organisational teams in the CDSCAM platform.
package teams

import "time"

// Team represents an organisational team that users can belong to.
type Team struct {
	ID          int64
	Name        string
	Description string
	Active      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
