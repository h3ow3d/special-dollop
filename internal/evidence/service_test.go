package evidence

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// ── in-memory repository ──────────────────────────────────────────────────────

type memRepository struct {
	digests  map[string]*ArtifactDigest // key: "<inventoryItemID>/<digest>"
	tags     map[string]*RepositoryTag  // key: "<inventoryItemID>/<tag>"
	evidence map[int64][]*DigestEvidence
	nextID   int64
}

func newMemRepo() *memRepository {
	return &memRepository{
		digests:  make(map[string]*ArtifactDigest),
		tags:     make(map[string]*RepositoryTag),
		evidence: make(map[int64][]*DigestEvidence),
		nextID:   1,
	}
}

func (r *memRepository) nextID64() int64 {
	id := r.nextID
	r.nextID++
	return id
}

func (r *memRepository) UpsertDigest(_ context.Context, d *ArtifactDigest) error {
	key := digestKey(d.InventoryItemID, d.Digest)
	if existing, ok := r.digests[key]; ok {
		existing.MediaType = d.MediaType
		existing.ArtifactType = d.ArtifactType
		existing.SizeBytes = d.SizeBytes
		existing.DiscoveryStatus = d.DiscoveryStatus
		existing.DiscoveryError = d.DiscoveryError
		existing.LastRefreshAt = d.LastRefreshAt
		*d = *existing
	} else {
		d.ID = r.nextID64()
		d.CreatedAt = time.Now()
		cp := *d
		r.digests[key] = &cp
	}
	return nil
}

func (r *memRepository) UpdateDigestStatus(_ context.Context, id int64, status DiscoveryStatus, errMsg string, discoveredAt time.Time) error {
	for _, d := range r.digests {
		if d.ID == id {
			d.DiscoveryStatus = status
			d.DiscoveryError = errMsg
			d.LastDiscoveredAt = discoveredAt
			return nil
		}
	}
	return nil
}

func (r *memRepository) GetDigestByID(_ context.Context, id int64) (*ArtifactDigest, error) {
	for _, d := range r.digests {
		if d.ID == id {
			cp := *d
			cp.Evidence = append([]*DigestEvidence(nil), r.evidence[id]...)
			return &cp, nil
		}
	}
	return nil, nil
}

func (r *memRepository) ListDigestsByItem(_ context.Context, inventoryItemID int64) ([]*ArtifactDigest, error) {
	var out []*ArtifactDigest
	for _, d := range r.digests {
		if d.InventoryItemID == inventoryItemID {
			cp := *d
			cp.Evidence = append([]*DigestEvidence(nil), r.evidence[d.ID]...)
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *memRepository) UpsertTag(_ context.Context, tag *RepositoryTag) error {
	key := tagKey(tag.InventoryItemID, tag.Tag)
	if existing, ok := r.tags[key]; ok {
		existing.ArtifactDigestID = tag.ArtifactDigestID
		existing.LastSeenAt = tag.LastSeenAt
		tag.ID = existing.ID
		tag.FirstSeenAt = existing.FirstSeenAt
	} else {
		tag.ID = r.nextID64()
		tag.FirstSeenAt = time.Now()
		cp := *tag
		r.tags[key] = &cp
	}
	return nil
}

func (r *memRepository) ListTagsByItem(_ context.Context, inventoryItemID int64) ([]*RepositoryTag, error) {
	var out []*RepositoryTag
	for _, t := range r.tags {
		if t.InventoryItemID == inventoryItemID {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *memRepository) ReplaceEvidence(_ context.Context, artifactDigestID int64, ev []*DigestEvidence) error {
	cp := make([]*DigestEvidence, len(ev))
	copy(cp, ev)
	r.evidence[artifactDigestID] = cp
	return nil
}

func (r *memRepository) GetSummaries(_ context.Context) (map[int64]*RepositorySummary, error) {
	return nil, nil
}

func digestKey(itemID int64, digest string) string {
	return fmt.Sprintf("%d/%s", itemID, digest)
}
func tagKey(itemID int64, tag string) string {
	return fmt.Sprintf("%d/%s", itemID, tag)
}

// ── fake discoverer ───────────────────────────────────────────────────────────

type fakeDiscoverer struct {
	tags      []string
	tagErr    error
	tagMap    map[string]*TagResolution // tag → resolution
	resolveErrs map[string]error
	referrers map[string][]*DigestEvidence
	referrerWarnings map[string][]string
	referrerErr map[string]error
}

func (d *fakeDiscoverer) ListTags(_ context.Context, _, _ string) ([]string, error) {
	if d.tagErr != nil {
		return nil, d.tagErr
	}
	return d.tags, nil
}

func (d *fakeDiscoverer) ResolveTag(_ context.Context, _, _, tag string) (*TagResolution, error) {
	if d.resolveErrs != nil {
		if err, ok := d.resolveErrs[tag]; ok {
			return nil, err
		}
	}
	if d.tagMap != nil {
		if r, ok := d.tagMap[tag]; ok {
			return r, nil
		}
	}
	return nil, errors.New("unknown tag: " + tag)
}

func (d *fakeDiscoverer) ListReferrers(_ context.Context, _, _, digest string) ([]*DigestEvidence, []string, error) {
	if d.referrerErr != nil {
		if err, ok := d.referrerErr[digest]; ok {
			return nil, nil, err
		}
	}
	var warnings []string
	if d.referrerWarnings != nil {
		warnings = d.referrerWarnings[digest]
	}
	return d.referrers[digest], warnings, nil
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestRefreshRepositorySuccess(t *testing.T) {
	repo := newMemRepo()
	disc := &fakeDiscoverer{
		tags: []string{"latest", "v1.0.0"},
		tagMap: map[string]*TagResolution{
			"latest": {Tag: "latest", Digest: "sha256:abc", MediaType: "application/vnd.oci.image.manifest.v1+json"},
			"v1.0.0": {Tag: "v1.0.0", Digest: "sha256:def", MediaType: "application/vnd.oci.image.manifest.v1+json"},
		},
		referrers: map[string][]*DigestEvidence{
			"sha256:abc": {{Type: EvidenceTypeSignature, Name: "sig", Digest: "sha256:sig1"}},
			"sha256:def": {{Type: EvidenceTypeSBOM, Name: "sbom", Digest: "sha256:sbom1"}},
		},
	}
	svc := NewService(repo, disc)

	if err := svc.RefreshRepository(context.Background(), DiscoveryTarget{
		InventoryItemID: 1,
		Registry:        "ghcr.io",
		Repository:      "org/repo",
	}); err != nil {
		t.Fatalf("RefreshRepository: %v", err)
	}

	digests, err := svc.ListDigestsByItem(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListDigestsByItem: %v", err)
	}
	if len(digests) != 2 {
		t.Fatalf("expected 2 digests, got %d", len(digests))
	}
	for _, d := range digests {
		if d.DiscoveryStatus != DiscoveryStatusSuccess {
			t.Errorf("expected success for digest %q, got %q", d.Digest, d.DiscoveryStatus)
		}
		if len(d.Evidence) != 1 {
			t.Errorf("expected 1 evidence for digest %q, got %d", d.Digest, len(d.Evidence))
		}
	}

	tags, err := svc.ListTagsByItem(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListTagsByItem: %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(tags))
	}
}

func TestRefreshRepositorySharedDigest(t *testing.T) {
	// Two tags pointing to the same digest: only one ArtifactDigest row should be created.
	repo := newMemRepo()
	disc := &fakeDiscoverer{
		tags: []string{"latest", "v2.0.0"},
		tagMap: map[string]*TagResolution{
			"latest": {Tag: "latest", Digest: "sha256:same"},
			"v2.0.0": {Tag: "v2.0.0", Digest: "sha256:same"},
		},
		referrers: map[string][]*DigestEvidence{
			"sha256:same": {{Type: EvidenceTypeSignature, Digest: "sha256:sig"}},
		},
	}
	svc := NewService(repo, disc)

	if err := svc.RefreshRepository(context.Background(), DiscoveryTarget{
		InventoryItemID: 2,
		Registry:        "ghcr.io",
		Repository:      "org/repo",
	}); err != nil {
		t.Fatalf("RefreshRepository: %v", err)
	}

	digests, _ := svc.ListDigestsByItem(context.Background(), 2)
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(digests))
	}
	tags, _ := svc.ListTagsByItem(context.Background(), 2)
	if len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(tags))
	}
}

func TestRefreshRepositoryListTagsFailure(t *testing.T) {
	repo := newMemRepo()
	disc := &fakeDiscoverer{tagErr: errors.New("network error")}
	svc := NewService(repo, disc)

	err := svc.RefreshRepository(context.Background(), DiscoveryTarget{
		InventoryItemID: 3,
		Registry:        "ghcr.io",
		Repository:      "org/repo",
	})
	if err == nil {
		t.Fatal("expected error when ListTags fails")
	}
}

func TestRefreshRepositoryTagResolutionSkipped(t *testing.T) {
	// One tag resolves fine; the other fails. Only one digest should be created.
	repo := newMemRepo()
	disc := &fakeDiscoverer{
		tags: []string{"latest", "broken"},
		tagMap: map[string]*TagResolution{
			"latest": {Tag: "latest", Digest: "sha256:ok"},
		},
		resolveErrs: map[string]error{"broken": errors.New("not found")},
		referrers:   map[string][]*DigestEvidence{"sha256:ok": {}},
	}
	svc := NewService(repo, disc)

	if err := svc.RefreshRepository(context.Background(), DiscoveryTarget{
		InventoryItemID: 4,
		Registry:        "ghcr.io",
		Repository:      "org/repo",
	}); err != nil {
		t.Fatalf("RefreshRepository: %v", err)
	}

	digests, _ := svc.ListDigestsByItem(context.Background(), 4)
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest (broken tag skipped), got %d", len(digests))
	}
}

func TestRefreshRepositoryReferrerFailureRecorded(t *testing.T) {
	repo := newMemRepo()
	disc := &fakeDiscoverer{
		tags:    []string{"v1"},
		tagMap:  map[string]*TagResolution{"v1": {Tag: "v1", Digest: "sha256:bad"}},
		referrerErr: map[string]error{"sha256:bad": errors.New("referrers unavailable")},
	}
	svc := NewService(repo, disc)

	if err := svc.RefreshRepository(context.Background(), DiscoveryTarget{
		InventoryItemID: 5,
		Registry:        "ghcr.io",
		Repository:      "org/repo",
	}); err != nil {
		t.Fatalf("RefreshRepository: %v", err)
	}

	digests, _ := svc.ListDigestsByItem(context.Background(), 5)
	if len(digests) != 1 {
		t.Fatalf("expected 1 digest, got %d", len(digests))
	}
	if digests[0].DiscoveryStatus != DiscoveryStatusFailed {
		t.Fatalf("expected failed status, got %q", digests[0].DiscoveryStatus)
	}
}

