package security

import (
	"context"
	"net/http"
	"strings"

	"github.com/h3ow3d/special-dollop/internal/domain"
)

type ctxKey string

const userKey ctxKey = "currentUser"

func UserFromContext(ctx context.Context) (domain.User, bool) {
	u, ok := ctx.Value(userKey).(domain.User)
	return u, ok
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("clph_session")
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, domain.User{Role: domain.RoleViewer})))
			return
		}
		parts := strings.Split(cookie.Value, "|")
		if len(parts) < 4 {
			http.Error(w, "invalid session", http.StatusUnauthorized)
			return
		}
		u := domain.User{GitHubUser: parts[0], Email: parts[1], OIDCSubject: parts[2], Role: domain.Role(parts[3]), DisplayName: parts[0]}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

func RequireRole(roles ...domain.Role) func(http.Handler) http.Handler {
	allowed := map[domain.Role]struct{}{}
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			if _, exists := allowed[u.Role]; !exists {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
