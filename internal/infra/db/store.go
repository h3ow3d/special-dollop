package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/h3ow3d/special-dollop/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) CreateAssessment(ctx context.Context, in domain.Assessment) (domain.Assessment, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO assessments (
assessment_id,status,created_date,review_date,assessment_owner,artefact_name,artefact_type,artefact_digest,artefact_registry,repository_url
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
RETURNING id`,
		in.AssessmentID, in.Status, in.CreatedAt, in.ReviewDate, in.OwnerUserID, in.ArtefactName, in.ArtefactType, in.ArtefactDigest, in.ArtefactRegistry, in.RepositoryURL,
	)
	if err := row.Scan(&in.ID); err != nil {
		return domain.Assessment{}, err
	}
	return in, nil
}

func (s *Store) ListAssessments(ctx context.Context) ([]domain.Assessment, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,assessment_id,status,created_date,review_date,assessment_owner,artefact_name,artefact_type,artefact_digest,artefact_registry,repository_url,outcome,pattern FROM assessments WHERE deleted_at IS NULL ORDER BY created_date DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]domain.Assessment, 0)
	for rows.Next() {
		var a domain.Assessment
		var outcome, pattern *string
		if err := rows.Scan(&a.ID, &a.AssessmentID, &a.Status, &a.CreatedAt, &a.ReviewDate, &a.OwnerUserID, &a.ArtefactName, &a.ArtefactType, &a.ArtefactDigest, &a.ArtefactRegistry, &a.RepositoryURL, &outcome, &pattern); err != nil {
			return nil, err
		}
		if outcome != nil {
			o := domain.Outcome(*outcome)
			a.Outcome = &o
		}
		if pattern != nil {
			p := domain.Pattern(*pattern)
			a.Pattern = &p
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetAssessmentByID(ctx context.Context, id int64) (domain.Assessment, error) {
	var a domain.Assessment
	var outcome, pattern *string
	err := s.pool.QueryRow(ctx, `
SELECT id,assessment_id,status,created_date,review_date,assessment_owner,artefact_name,artefact_type,artefact_digest,artefact_registry,repository_url,
outcome,outcome_rationale,required_controls,pattern,pattern_rationale
FROM assessments WHERE id=$1 AND deleted_at IS NULL`, id).
		Scan(&a.ID, &a.AssessmentID, &a.Status, &a.CreatedAt, &a.ReviewDate, &a.OwnerUserID, &a.ArtefactName, &a.ArtefactType, &a.ArtefactDigest, &a.ArtefactRegistry, &a.RepositoryURL, &outcome, &a.OutcomeRationale, &a.RequiredControls, &pattern, &a.PatternRationale)
	if err != nil {
		return domain.Assessment{}, err
	}
	if outcome != nil {
		o := domain.Outcome(*outcome)
		a.Outcome = &o
	}
	if pattern != nil {
		p := domain.Pattern(*pattern)
		a.Pattern = &p
	}
	return a, nil
}

func (s *Store) UpdateOutcome(ctx context.Context, id int64, outcome domain.Outcome, rationale, controls string, pattern domain.Pattern, patternRationale string, status domain.AssessmentStatus) error {
	cmd, err := s.pool.Exec(ctx, `UPDATE assessments SET outcome=$2,outcome_rationale=$3,required_controls=$4,pattern=$5,pattern_rationale=$6,status=$7,updated_at=now() WHERE id=$1 AND deleted_at IS NULL`, id, outcome, rationale, controls, pattern, patternRationale, status)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return errors.New("assessment not found")
	}
	return nil
}

func (s *Store) AddApproval(ctx context.Context, approval domain.Approval) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO approvals (assessment_id,approver_name,approver_identity,approver_role,approval_time,approval_comments) VALUES ($1,$2,$3,$4,$5,$6)`,
		approval.AssessmentID, approval.ApproverName, approval.ApproverIdentity, approval.ApproverRole, approval.ApprovalTime, approval.ApprovalComments)
	return err
}

func (s *Store) SetAssessmentStatus(ctx context.Context, id int64, status domain.AssessmentStatus) error {
	_, err := s.pool.Exec(ctx, `UPDATE assessments SET status=$2,updated_at=now() WHERE id=$1 AND deleted_at IS NULL`, id, status)
	return err
}

func (s *Store) SaveAttestation(ctx context.Context, att domain.Attestation) (domain.Attestation, error) {
	err := s.pool.QueryRow(ctx, `INSERT INTO attestations (assessment_id,statement_json,signature,signed_by,signed_email,oidc_subject,signing_time) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		att.AssessmentID, att.StatementJSON, att.Signature, att.SignedBy, att.SignedEmail, att.OIDCSubject, att.SigningTime).Scan(&att.ID)
	if err != nil {
		return domain.Attestation{}, err
	}
	return att, nil
}

func (s *Store) UpdateAttestationPublication(ctx context.Context, attestationID int64, registry, reference string, publishedAt time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE attestations SET oci_registry=$2,oci_reference=$3,published_at=$4 WHERE id=$1 AND deleted_at IS NULL`, attestationID, registry, reference, publishedAt)
	return err
}

func (s *Store) CreateOrUpdateUser(ctx context.Context, user domain.User) (domain.User, error) {
	err := s.pool.QueryRow(ctx, `
INSERT INTO users (github_username,email,oidc_subject,display_name,role,last_login_at)
VALUES ($1,$2,$3,$4,$5,now())
ON CONFLICT (github_username) DO UPDATE SET email=EXCLUDED.email,oidc_subject=EXCLUDED.oidc_subject,display_name=EXCLUDED.display_name,role=EXCLUDED.role,last_login_at=now(),deleted_at=NULL
RETURNING id,created_at,last_login_at`, user.GitHubUser, user.Email, user.OIDCSubject, user.DisplayName, user.Role).Scan(&user.ID, &user.CreatedAt, &user.LastLoginAt)
	if err != nil {
		return domain.User{}, err
	}
	return user, nil
}

func (s *Store) AppendAuditLog(ctx context.Context, log domain.AuditLog) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_logs (actor_user_id,event_type,entity_type,entity_id,payload) VALUES ($1,$2,$3,$4,$5)`, log.ActorUserID, log.EventType, log.EntityType, log.EntityID, log.Payload)
	return err
}

func (s *Store) SeedSampleData(ctx context.Context) error {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(1) FROM assessments WHERE deleted_at IS NULL`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO users (github_username,email,oidc_subject,display_name,role,last_login_at) VALUES ('sample.assessor','sample@example.com','oidc:sample','Sample Assessor','Assessor',now()) ON CONFLICT (github_username) DO NOTHING`)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO assessments (assessment_id,status,created_date,review_date,assessment_owner,artefact_name,artefact_type,artefact_digest,artefact_registry,repository_url)
SELECT 'SA-001','Draft',now(),now()+interval '365 day',id,'orders-api','application-container','sha256:abc123','registry:5000','https://github.com/h3ow3d/special-dollop' FROM users WHERE github_username='sample.assessor' LIMIT 1`)
	if err != nil {
		return fmt.Errorf("seed sample assessment: %w", err)
	}
	return nil
}
