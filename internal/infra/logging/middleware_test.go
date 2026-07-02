package logging

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/h3ow3d/special-dollop/internal/infra/security"
)

type captureHandler struct {
	mu      sync.Mutex
	records []map[string]any
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler        { return h }
func (h *captureHandler) WithGroup(string) slog.Handler             { return h }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	entry := map[string]any{"msg": r.Message}
	r.Attrs(func(attr slog.Attr) bool {
		entry[attr.Key] = attr.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, entry)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) lastRecord() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == 0 {
		return nil
	}
	return h.records[len(h.records)-1]
}

func TestRequestLoggerIncludesAuthenticatedFields(t *testing.T) {
	old := slog.Default()
	capture := &captureHandler{}
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(old) })

	oauth := security.NewOAuthHandler(security.GitHubOAuthConfig{}, []byte("12345678901234567890123456789012"))
	session := domain.UserSession{
		GitHubUser: domain.User{GitHubUsername: "alice"},
		RoleSlug:   "assessor",
		TeamName:   "Blue Team",
		Active:     true,
	}

	w := httptest.NewRecorder()
	if err := oauth.SetSessionCookie(w, session); err != nil {
		t.Fatalf("SetSessionCookie: %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "/inventory", nil)
	req.AddCookie(cookies[0])
	rr := httptest.NewRecorder()

	handler := oauth.AuthMiddleware(RequestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})))

	handler.ServeHTTP(rr, req)

	record := capture.lastRecord()
	if record == nil {
		t.Fatal("expected a log record")
	}
	if got := record["msg"]; got != "http request completed" {
		t.Fatalf("expected request log message, got %v", got)
	}
	if got := record["user"]; got != "alice" {
		t.Fatalf("expected user alice, got %v", got)
	}
	if got := record["role"]; got != "assessor" {
		t.Fatalf("expected role assessor, got %v", got)
	}
	if got := record["team"]; got != "Blue Team" {
		t.Fatalf("expected team Blue Team, got %v", got)
	}
	if got := record["status"]; got != int64(http.StatusAccepted) {
		t.Fatalf("expected status %d, got %v", http.StatusAccepted, got)
	}
}

func TestPanicRecoveryLogsAndReturns500(t *testing.T) {
	old := slog.Default()
	capture := &captureHandler{}
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(old) })

	r := chi.NewRouter()
	r.Use(PanicRecovery)
	r.Get("/panic", func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}

	record := capture.lastRecord()
	if record == nil {
		t.Fatal("expected panic log record")
	}
	if got := record["msg"]; got != "panic recovered" {
		t.Fatalf("expected panic message, got %v", got)
	}
	if got := record["route"]; got != "/panic" {
		t.Fatalf("expected route /panic, got %v", got)
	}
	if got := record["panic_value"]; got != "boom" {
		t.Fatalf("expected panic value boom, got %v", got)
	}
	if got := record["stack_trace"]; got == "" {
		t.Fatal("expected stack trace to be present")
	}
}
