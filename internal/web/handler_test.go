package web

import (
"context"
"net/http"
"net/http/httptest"
"testing"

"github.com/h3ow3d/special-dollop/internal/app"
"github.com/h3ow3d/special-dollop/internal/domain"
"github.com/h3ow3d/special-dollop/internal/infra/security"
"github.com/h3ow3d/special-dollop/internal/infra/session"
)

type fakeBuilder struct{}

func (f *fakeBuilder) Build(_ *domain.AssessmentState) ([]byte, error) {
return []byte(`{"ok":true}`), nil
}

type fakeSigner struct{}

func (f *fakeSigner) Sign(_ context.Context, _ []byte, _ domain.User) (string, error) {
return "dGVzdHNpZw==", nil
}

type fakePublisher struct{}

func (f *fakePublisher) Publish(_ context.Context, _, _ string, _ []byte, _, _ string) (string, error) {
return "registry/ref@sha256:abc", nil
}

const testHashKey = "test-hash-key-32-bytes-long-fill"

func newTestHandler(t *testing.T) (*Handler, *security.OAuthHandler) {
t.Helper()
svc := app.NewService(session.NewStore(), &fakeBuilder{}, &fakeSigner{}, &fakePublisher{})
oauth := security.NewOAuthHandler(security.GitHubOAuthConfig{}, []byte(testHashKey))
h, err := NewHandler(svc, oauth)
if err != nil {
t.Fatalf("NewHandler: %v", err)
}
return h, oauth
}

func TestHealthLive(t *testing.T) {
h, _ := newTestHandler(t)
r := httptest.NewRequest(http.MethodGet, "/health/live", nil)
w := httptest.NewRecorder()
h.Router([]byte("12345678901234567890123456789012")).ServeHTTP(w, r)
if w.Code != http.StatusOK {
t.Fatalf("expected 200 got %d", w.Code)
}
}

func TestHealthReady(t *testing.T) {
h, _ := newTestHandler(t)
r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
w := httptest.NewRecorder()
h.Router([]byte("12345678901234567890123456789012")).ServeHTTP(w, r)
if w.Code != http.StatusOK {
t.Fatalf("expected 200 got %d", w.Code)
}
}

func TestHomeRendersForUnauthenticated(t *testing.T) {
h, _ := newTestHandler(t)
r := httptest.NewRequest(http.MethodGet, "/", nil)
w := httptest.NewRecorder()
h.Router([]byte("12345678901234567890123456789012")).ServeHTTP(w, r)
if w.Code != http.StatusOK {
t.Fatalf("expected 200 for unauthenticated home, got %d", w.Code)
}
}

func TestWizardProtectedWithoutAuth(t *testing.T) {
h, _ := newTestHandler(t)
r := httptest.NewRequest(http.MethodGet, "/wizard/new", nil)
w := httptest.NewRecorder()
h.Router([]byte("12345678901234567890123456789012")).ServeHTTP(w, r)
// Should redirect to / because RequireAuth is applied
if w.Code != http.StatusFound {
t.Fatalf("expected redirect for unauthenticated wizard, got %d", w.Code)
}
if loc := w.Header().Get("Location"); loc != "/" {
t.Fatalf("expected redirect to / got %s", loc)
}
}
