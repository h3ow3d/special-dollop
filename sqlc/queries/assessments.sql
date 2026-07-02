-- name: ListAssessments :many
SELECT id, assessment_id, status, created_date, review_date, assessment_owner, artefact_name, artefact_type, artefact_digest, artefact_registry, repository_url, outcome, pattern
FROM assessments
WHERE deleted_at IS NULL
ORDER BY created_date DESC;

-- name: GetAssessment :one
SELECT id, assessment_id, status, created_date, review_date, assessment_owner, artefact_name, artefact_type, artefact_digest, artefact_registry, repository_url, outcome, pattern
FROM assessments
WHERE id=$1 AND deleted_at IS NULL;
