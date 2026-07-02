package inventory

import (
	"context"
	"testing"
	"time"
)

// ── in-memory test repository ─────────────────────────────────────────────────

type memRepo struct {
	items  []*InventoryItem
	nextID int64
}

func newMemRepo() *memRepo { return &memRepo{nextID: 1} }

func (r *memRepo) Create(_ context.Context, item *InventoryItem) error {
	item.ID = r.nextID
	r.nextID++
	item.CreatedAt = time.Now()
	item.UpdatedAt = time.Now()
	cp := *item
	r.items = append(r.items, &cp)
	return nil
}

func (r *memRepo) GetByID(_ context.Context, id int64) (*InventoryItem, error) {
	for _, item := range r.items {
		if item.ID == id {
			cp := *item
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (r *memRepo) Update(_ context.Context, item *InventoryItem) error {
	for i, existing := range r.items {
		if existing.ID == item.ID {
			cp := *item
			cp.UpdatedAt = time.Now()
			r.items[i] = &cp
			item.UpdatedAt = cp.UpdatedAt
			return nil
		}
	}
	return ErrNotFound
}

func (r *memRepo) SetActive(_ context.Context, id int64, active bool) error {
	for _, item := range r.items {
		if item.ID == id {
			item.Active = active
			return nil
		}
	}
	return ErrNotFound
}

func (r *memRepo) List(_ context.Context) ([]*InventoryItemWithTeam, error) {
	out := make([]*InventoryItemWithTeam, 0, len(r.items))
	for _, item := range r.items {
		cp := *item
		out = append(out, &InventoryItemWithTeam{InventoryItem: cp})
	}
	return out, nil
}

func (r *memRepo) ListByTeam(_ context.Context, teamID int64) ([]*InventoryItemWithTeam, error) {
	var out []*InventoryItemWithTeam
	for _, item := range r.items {
		if item.TeamID == teamID {
			cp := *item
			out = append(out, &InventoryItemWithTeam{InventoryItem: cp})
		}
	}
	return out, nil
}

func (r *memRepo) CountByTeam(_ context.Context) (map[int64]int, error) {
	counts := make(map[int64]int)
	for _, item := range r.items {
		if item.Active {
			counts[item.TeamID]++
		}
	}
	return counts, nil
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestCreate(t *testing.T) {
	svc := NewService(newMemRepo(), nil)
	item := &InventoryItem{
		Name:     "proverjay",
		TeamID:   1,
		Registry: "ghcr.io",
	}
	if err := svc.Create(context.Background(), item); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if item.ID == 0 {
		t.Fatal("expected non-zero ID after Create")
	}
	if !item.Active {
		t.Fatal("expected item to be active after Create")
	}
}

func TestGetByID(t *testing.T) {
	svc := NewService(newMemRepo(), nil)
	item := &InventoryItem{Name: "harbor", TeamID: 1}
	_ = svc.Create(context.Background(), item)

	got, err := svc.GetByID(context.Background(), item.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Name != "harbor" {
		t.Fatalf("expected name 'harbor', got %q", got.Name)
	}
}

func TestGetByID_NotFound(t *testing.T) {
	svc := NewService(newMemRepo(), nil)
	_, err := svc.GetByID(context.Background(), 999)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdate(t *testing.T) {
	svc := NewService(newMemRepo(), nil)
	item := &InventoryItem{Name: "cert-manager", TeamID: 2}
	_ = svc.Create(context.Background(), item)

	item.Description = "Certificate management tooling"
	item.Registry = "ghcr.io"
	if err := svc.Update(context.Background(), item); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := svc.GetByID(context.Background(), item.ID)
	if got.Description != "Certificate management tooling" {
		t.Fatalf("expected updated description, got %q", got.Description)
	}
}

func TestSetActive(t *testing.T) {
	svc := NewService(newMemRepo(), nil)
	item := &InventoryItem{Name: "trivy", TeamID: 3}
	_ = svc.Create(context.Background(), item)

	if err := svc.SetActive(context.Background(), item.ID, false); err != nil {
		t.Fatalf("SetActive: %v", err)
	}
	got, _ := svc.GetByID(context.Background(), item.ID)
	if got.Active {
		t.Fatal("expected item to be inactive after SetActive(false)")
	}
}

func TestTeamOwnership(t *testing.T) {
	svc := NewService(newMemRepo(), nil)
	_ = svc.Create(context.Background(), &InventoryItem{Name: "item-a", TeamID: 1})
	_ = svc.Create(context.Background(), &InventoryItem{Name: "item-b", TeamID: 1})
	_ = svc.Create(context.Background(), &InventoryItem{Name: "item-c", TeamID: 2})

	team1Items, err := svc.ListByTeam(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListByTeam: %v", err)
	}
	if len(team1Items) != 2 {
		t.Fatalf("expected 2 items for team 1, got %d", len(team1Items))
	}

	team2Items, _ := svc.ListByTeam(context.Background(), 2)
	if len(team2Items) != 1 {
		t.Fatalf("expected 1 item for team 2, got %d", len(team2Items))
	}
}

func TestCountByTeam(t *testing.T) {
	svc := NewService(newMemRepo(), nil)
	_ = svc.Create(context.Background(), &InventoryItem{Name: "a", TeamID: 1})
	_ = svc.Create(context.Background(), &InventoryItem{Name: "b", TeamID: 1})
	_ = svc.Create(context.Background(), &InventoryItem{Name: "c", TeamID: 2})

	// Deactivate one item in team 1.
	items, _ := svc.List(context.Background())
	_ = svc.SetActive(context.Background(), items[0].ID, false)

	counts, err := svc.CountByTeam(context.Background())
	if err != nil {
		t.Fatalf("CountByTeam: %v", err)
	}
	if counts[1] != 1 {
		t.Fatalf("expected 1 active item for team 1, got %d", counts[1])
	}
	if counts[2] != 1 {
		t.Fatalf("expected 1 active item for team 2, got %d", counts[2])
	}
}

func TestInventoryVisibility(t *testing.T) {
	svc := NewService(newMemRepo(), nil)
	for _, name := range []string{"a", "b", "c"} {
		_ = svc.Create(context.Background(), &InventoryItem{Name: name, TeamID: 1})
	}
	items, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
}
