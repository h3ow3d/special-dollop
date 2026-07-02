package audit_test

import (
	"context"
	"testing"

	"github.com/h3ow3d/special-dollop/internal/audit"
)

// ── in-memory fake ───────────────────────────────────────────────────────────

type fakeRepo struct {
	entries []*audit.Entry
}

func (r *fakeRepo) Record(_ context.Context, e *audit.Entry) error {
	e.ID = int64(len(r.entries) + 1)
	cp := *e
	r.entries = append(r.entries, &cp)
	return nil
}

func (r *fakeRepo) ListByUser(_ context.Context, userID int64, limit int) ([]*audit.Entry, error) {
	var out []*audit.Entry
	for _, e := range r.entries {
		if e.UserID != nil && *e.UserID == userID {
			cp := *e
			out = append(out, &cp)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestRecord(t *testing.T) {
	repo := &fakeRepo{}
	svc := audit.NewService(repo)

	id := int64(7)
	svc.Record(context.Background(), &id, audit.ActionLogin,
		map[string]any{"github_username": "alice"}, "127.0.0.1")

	if len(repo.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(repo.entries))
	}
	e := repo.entries[0]
	if e.Action != audit.ActionLogin {
		t.Fatalf("expected %s, got %s", audit.ActionLogin, e.Action)
	}
	if *e.UserID != 7 {
		t.Fatalf("expected userID 7, got %d", *e.UserID)
	}
}

func TestRecordNilUser(t *testing.T) {
	repo := &fakeRepo{}
	svc := audit.NewService(repo)
	// Should not panic when userID is nil.
	svc.Record(context.Background(), nil, audit.ActionLogout, nil, "")
	if len(repo.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(repo.entries))
	}
}
