-- +goose Up
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    github_username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    oidc_subject TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS assessments (
    id BIGSERIAL PRIMARY KEY,
    assessment_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    created_date TIMESTAMPTZ NOT NULL,
    review_date TIMESTAMPTZ NOT NULL,
    assessment_owner BIGINT NOT NULL REFERENCES users(id),
    artefact_name TEXT NOT NULL,
    artefact_type TEXT NOT NULL,
    artefact_digest TEXT NOT NULL,
    artefact_registry TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    sensitivity_notes TEXT NOT NULL DEFAULT '',
    privilege_notes TEXT NOT NULL DEFAULT '',
    provenance_notes TEXT NOT NULL DEFAULT '',
    verifiability_notes TEXT NOT NULL DEFAULT '',
    traceability_notes TEXT NOT NULL DEFAULT '',
    operational_notes TEXT NOT NULL DEFAULT '',
    recoverability_notes TEXT NOT NULL DEFAULT '',
    supply_chain_notes TEXT NOT NULL DEFAULT '',
    outcome TEXT,
    outcome_rationale TEXT NOT NULL DEFAULT '',
    required_controls TEXT NOT NULL DEFAULT '',
    pattern TEXT,
    pattern_rationale TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS participants (
    id BIGSERIAL PRIMARY KEY,
    assessment_id BIGINT NOT NULL REFERENCES assessments(id),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    organisation TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS evidence (
    id BIGSERIAL PRIMARY KEY,
    assessment_id BIGINT NOT NULL REFERENCES assessments(id),
    evidence_type TEXT NOT NULL,
    reviewed BOOLEAN NOT NULL DEFAULT FALSE,
    reference TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS notes (
    id BIGSERIAL PRIMARY KEY,
    assessment_id BIGINT NOT NULL REFERENCES assessments(id),
    discussion_summary TEXT NOT NULL,
    concerns TEXT NOT NULL,
    assumptions TEXT NOT NULL,
    constraints TEXT NOT NULL,
    rationale TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS approvals (
    id BIGSERIAL PRIMARY KEY,
    assessment_id BIGINT NOT NULL REFERENCES assessments(id),
    approver_name TEXT NOT NULL,
    approver_identity TEXT NOT NULL,
    approver_role TEXT NOT NULL,
    approval_time TIMESTAMPTZ NOT NULL,
    approval_comments TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attestations (
    id BIGSERIAL PRIMARY KEY,
    assessment_id BIGINT NOT NULL REFERENCES assessments(id),
    statement_json JSONB NOT NULL,
    signature TEXT NOT NULL,
    signed_by TEXT NOT NULL,
    signed_email TEXT NOT NULL,
    oidc_subject TEXT NOT NULL,
    signing_time TIMESTAMPTZ NOT NULL,
    oci_registry TEXT,
    oci_reference TEXT,
    published_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id BIGINT REFERENCES users(id),
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

-- +goose Down
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS attestations;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS participants;
DROP TABLE IF EXISTS assessments;
DROP TABLE IF EXISTS users;
