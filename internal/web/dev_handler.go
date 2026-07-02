package web

import (
	"net/url"
	"path"
	"strings"
)

func sanitizeReturnTarget(v string) string {
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Opaque != "" {
		return ""
	}
	rawPath := u.EscapedPath()
	if rawPath == "" {
		rawPath = u.Path
	}
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil || !strings.HasPrefix(decodedPath, "/") || strings.HasPrefix(decodedPath, "//") || strings.Contains(decodedPath, "\\") {
		return ""
	}
	if len(decodedPath) > 1 && (decodedPath[1] == '/' || decodedPath[1] == '\\') {
		return ""
	}
	cleanedPath := path.Clean(decodedPath)
	if cleanedPath == "." || !strings.HasPrefix(cleanedPath, "/") || strings.HasPrefix(cleanedPath, "//") || !hasAllowedDevReturnPrefix(cleanedPath) {
		return ""
	}
	if len(cleanedPath) > 1 && (cleanedPath[1] == '/' || cleanedPath[1] == '\\') {
		return ""
	}
	if u.RawQuery != "" {
		return cleanedPath + "?" + u.RawQuery
	}
	return cleanedPath
}

func hasAllowedDevReturnPrefix(v string) bool {
	switch {
	case strings.HasPrefix(v, "/dashboard"),
		strings.HasPrefix(v, "/assessments"),
		strings.HasPrefix(v, "/profile"),
		strings.HasPrefix(v, "/wizard"),
		strings.HasPrefix(v, "/admin"),
		strings.HasPrefix(v, "/oci"),
		v == "/":
		return true
	default:
		return false
	}
}
