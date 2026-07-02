package oci

import "testing"

func TestNormalizeReferenceFullDigest(t *testing.T) {
	got, err := normalizeReference("ghcr.io", "ghcr.io/h3ow3d/proverjay@sha256:e48baa02c6cf8cc44b076b6a114e81d9a48427d385b5fdad88b2fa4dc3385d44")
	if err != nil {
		t.Fatalf("normalizeReference: %v", err)
	}
	if got.Registry != "ghcr.io" || got.Repository != "h3ow3d/proverjay" {
		t.Fatalf("unexpected repository: %+v", got)
	}
	if got.Reference != "sha256:e48baa02c6cf8cc44b076b6a114e81d9a48427d385b5fdad88b2fa4dc3385d44" {
		t.Fatalf("unexpected digest reference: %s", got.Reference)
	}
}

func TestNormalizeReferencePrefixesRegistryWhenNeeded(t *testing.T) {
	got, err := normalizeReference("ghcr.io", "h3ow3d/proverjay@sha256:e48baa02c6cf8cc44b076b6a114e81d9a48427d385b5fdad88b2fa4dc3385d44")
	if err != nil {
		t.Fatalf("normalizeReference: %v", err)
	}
	if got.String() != "ghcr.io/h3ow3d/proverjay@sha256:e48baa02c6cf8cc44b076b6a114e81d9a48427d385b5fdad88b2fa4dc3385d44" {
		t.Fatalf("unexpected normalized reference: %s", got.String())
	}
}

func TestNormalizeReferenceRejectsRegistryMismatch(t *testing.T) {
	_, err := normalizeReference("ghcr.io", "example.com/h3ow3d/proverjay:latest")
	if err == nil {
		t.Fatal("expected registry mismatch error")
	}
}

func TestPredicateTypeFromEnvelope(t *testing.T) {
	envelope := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"eyJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9jbHBoLmludGVybmFsL3N1aXRhYmlsaXR5L3YxIn0=","signatures":[{"sig":"abc"}]}`)
	if got := predicateTypeFromEnvelope(envelope); got != clphPredicateType {
		t.Fatalf("unexpected predicate type: %q", got)
	}
}
