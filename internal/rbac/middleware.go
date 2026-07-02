package rbac

import (
	"net/http"

	"github.com/h3ow3d/special-dollop/internal/infra/security"
)

// RequireRole returns HTTP middleware that allows only requests whose session
// carries one of the specified role slugs. All other authenticated requests
// receive HTTP 403; unauthenticated requests are redirected to the login page.
func RequireRole(roles ...RoleSlug) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[string(r)] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := security.SessionFromContext(r.Context())
			if !ok || session.UserID == 0 {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			if !session.Active {
				http.Error(w, "account is deactivated", http.StatusForbidden)
				return
			}
			if !allowed[session.RoleSlug] {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
