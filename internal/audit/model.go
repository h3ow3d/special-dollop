// Package audit provides audit logging for the CDSCAM platform.
package audit

import "time"

// Action identifies the type of auditable event.
type Action string

const (
	ActionLogin                  Action = "user.login"
	ActionLogout                 Action = "user.logout"
	ActionDevLogin               Action = "dev.login"
	ActionDevLogout              Action = "dev.logout"
	ActionRoleChanged            Action = "user.role_changed"
	ActionRoleImpersonation      Action = "Role Impersonation"
	ActionTeamChanged            Action = "user.team_changed"
	ActionUserActivated          Action = "user.activated"
	ActionUserDeactivated        Action = "user.deactivated"
	ActionBootstrapAdminAssigned Action = "Bootstrap Administrator Assigned"
)

// Entry is a single audit log record.
type Entry struct {
	ID        int64
	UserID    *int64
	Action    Action
	Detail    map[string]any
	IPAddress string
	CreatedAt time.Time
}
