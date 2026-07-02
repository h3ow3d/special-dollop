package teams_test

import (
	"context"
	"testing"

	"github.com/h3ow3d/special-dollop/internal/teams"
)

// ── in-memory fake ───────────────────────────────────────────────────────────

type fakeRepo struct {
	store  map[int64]*teams.Team
	nextID int64
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{store: make(map[int64]*teams.Team), nextID: 1}
}

func (r *fakeRepo) Create(_ context.Context, t *teams.Team) error {
	t.ID = r.nextID
	r.nextID++
	cp := *t
	r.store[t.ID] = &cp
	return nil
}

func (r *fakeRepo) GetByID(_ context.Context, id int64) (*teams.Team, error) {
	t, ok := r.store[id]
	if !ok {
		return nil, teams.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (r *fakeRepo) List(_ context.Context) ([]*teams.Team, error) {
	var out []*teams.Team
	for _, t := range r.store {
		cp := *t
		out = append(out, &cp)
	}
	return out, nil
}

func (r *fakeRepo) SetActive(_ context.Context, id int64, active bool) error {
	t, ok := r.store[id]
	if !ok {
		return teams.ErrNotFound
	}
	t.Active = active
	return nil
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestCreateTeam(t *testing.T) {
	svc := teams.NewService(newFakeRepo())
	team, err := svc.Create(context.Background(), "Platform Team", "Core platform engineers")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if team.ID == 0 {
		t.Fatal("expected non-zero ID")
	}
	if !team.Active {
		t.Fatal("new team should be active")
	}
}

func TestListTeams(t *testing.T) {
	svc := teams.NewService(newFakeRepo())
	_, _ = svc.Create(context.Background(), "Team A", "")
	_, _ = svc.Create(context.Background(), "Team B", "")

	ts, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ts) != 2 {
		t.Fatalf("expected 2 teams, got %d", len(ts))
	}
}

func TestSetTeamActive(t *testing.T) {
	svc := teams.NewService(newFakeRepo())
	team, _ := svc.Create(context.Background(), "Security Team", "")

	if err := svc.SetActive(context.Background(), team.ID, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	got, _ := svc.GetByID(context.Background(), team.ID)
	if got.Active {
		t.Fatal("expected team to be inactive")
	}
}
