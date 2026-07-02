package audit

import (
	"context"
	"log/slog"
)

// Service records audit events.
type Service struct {
	repo Repository
}

// NewService creates a Service backed by the provided Repository.
func NewService(repo Repository) *Service { return &Service{repo: repo} }

// Record writes an audit entry asynchronously. Errors are logged but not
// propagated so that audit failures never block user-facing operations.
func (s *Service) Record(ctx context.Context, userID *int64, action Action, detail map[string]any, ip string) {
	e := &Entry{
		UserID:    userID,
		Action:    action,
		Detail:    detail,
		IPAddress: ip,
	}
	if err := s.repo.Record(ctx, e); err != nil {
		slog.Warn("audit record failed",
			"operation", "audit.record",
			"user_id", userID,
			"action", action,
			"error", err.Error(),
		)
	}
}
