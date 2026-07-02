// Package rbac provides role-based access control for the CDSCAM platform.
package rbac

// RoleSlug is the string identifier of a built-in role.
type RoleSlug string

const (
	RoleAdministrator RoleSlug = "administrator"
	RoleAssessor      RoleSlug = "assessor"
	RoleReader        RoleSlug = "reader"
)
