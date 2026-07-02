// Package users defines the platform's user, role, and team domain models.
package users

import "time"

// User is the platform's persistent user entity.
type User struct {
	ID             int64
	GitHubUserID   int64
	GitHubUsername string
	DisplayName    string
	Email          string
	AvatarURL      string
	RoleID         int64
	TeamID         *int64
	Active         bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastLoginAt    *time.Time
}

// Role is a named set of permissions, seeded at startup.
type Role struct {
	ID   int64
	Name string
	Slug string
}

// RoleSlug constants for the three built-in roles.
const (
	RoleSlugAdministrator = "administrator"
	RoleSlugAssessor      = "assessor"
	RoleSlugReader        = "reader"
)
