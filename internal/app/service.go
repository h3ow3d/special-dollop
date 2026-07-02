package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/h3ow3d/special-dollop/internal/domain"
)

var ErrNotApproved = errors.New("assessment must be approved before attestation")

type Repository interface {
	CreateAssessment(ctx context.Context, in domain.Assessment) (domain.Assessment, error)
	ListAssessments(ctx context.Context) ([]domain.Assessment, error)
	GetAssessmentByID(ctx context.Context, id int64) (domain.Assessment, error)
	UpdateOutcome(ctx context.Context, id int64, outcome domain.Outcome, rationale, controls string, pattern domain.Pattern, patternRationale string, status domain.AssessmentStatus) error
	AddApproval(ctx context.Context, approval domain.Approval) error
	SetAssessmentStatus(ctx context.Context, id int64, status domain.AssessmentStatus) error
	SaveAttestation(ctx context.Context, att domain.Attestation) (domain.Attestation, error)
	GetAttestationByID(ctx context.Context, id int64) (domain.Attestation, error)
	UpdateAttestationPublication(ctx context.Context, attestationID int64, registry, reference string, publishedAt time.Time) error
	CreateOrUpdateUser(ctx context.Context, user domain.User) (domain.User, error)
	AppendAuditLog(ctx context.Context, log domain.AuditLog) error
}

type AttestationBuilder interface {
	Build(assessment domain.Assessment, approver string) ([]byte, error)
}

type Signer interface {
	Sign(ctx context.Context, payload []byte, user domain.User) (signature string, err error)
}

type OCIPublisher interface {
	Publish(ctx context.Context, registry string, artifactRef string, attestation []byte) (string, error)
}

type Service struct {
	repo    Repository
	build   AttestationBuilder
	signer  Signer
	publish OCIPublisher
}

func NewService(repo Repository, builder AttestationBuilder, signer Signer, publisher OCIPublisher) *Service {
	return &Service{repo: repo, build: builder, signer: signer, publish: publisher}
}

func (s *Service) Login(ctx context.Context, user domain.User) (domain.User, error) {
	u, err := s.repo.CreateOrUpdateUser(ctx, user)
	if err != nil {
		return domain.User{}, err
	}
	_ = s.repo.AppendAuditLog(ctx, domain.AuditLog{ActorUserID: &u.ID, EventType: "login", EntityType: "user", EntityID: fmt.Sprintf("%d", u.ID), Payload: u.GitHubUser})
	return u, nil
}

func (s *Service) CreateAssessment(ctx context.Context, actor domain.User, in domain.Assessment) (domain.Assessment, error) {
	if in.Status == "" {
		in.Status = domain.StatusDraft
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	out, err := s.repo.CreateAssessment(ctx, in)
	if err != nil {
		return domain.Assessment{}, err
	}
	_ = s.repo.AppendAuditLog(ctx, domain.AuditLog{ActorUserID: &actor.ID, EventType: "assessment creation", EntityType: "assessment", EntityID: fmt.Sprintf("%d", out.ID), Payload: out.AssessmentID})
	return out, nil
}

func (s *Service) ListAssessments(ctx context.Context) ([]domain.Assessment, error) {
	return s.repo.ListAssessments(ctx)
}

func (s *Service) GetAssessment(ctx context.Context, id int64) (domain.Assessment, error) {
	return s.repo.GetAssessmentByID(ctx, id)
}

func (s *Service) RecordOutcome(ctx context.Context, actor domain.User, id int64, outcome domain.Outcome, rationale, controls string, pattern domain.Pattern, patternRationale string) error {
	if err := s.repo.UpdateOutcome(ctx, id, outcome, rationale, controls, pattern, patternRationale, domain.StatusInReview); err != nil {
		return err
	}
	return s.repo.AppendAuditLog(ctx, domain.AuditLog{ActorUserID: &actor.ID, EventType: "assessment modification", EntityType: "assessment", EntityID: fmt.Sprintf("%d", id), Payload: string(outcome)})
}

func (s *Service) ApproveAssessment(ctx context.Context, actor domain.User, id int64, comments string) error {
	if err := s.repo.AddApproval(ctx, domain.Approval{
		AssessmentID:     id,
		ApproverName:     actor.DisplayName,
		ApproverIdentity: actor.GitHubUser,
		ApproverRole:     string(actor.Role),
		ApprovalTime:     time.Now().UTC(),
		ApprovalComments: comments,
	}); err != nil {
		return err
	}
	if err := s.repo.SetAssessmentStatus(ctx, id, domain.StatusApproved); err != nil {
		return err
	}
	return s.repo.AppendAuditLog(ctx, domain.AuditLog{ActorUserID: &actor.ID, EventType: "approval", EntityType: "assessment", EntityID: fmt.Sprintf("%d", id), Payload: comments})
}

func (s *Service) GenerateAndSignAttestation(ctx context.Context, actor domain.User, id int64) (domain.Attestation, error) {
	assessment, err := s.repo.GetAssessmentByID(ctx, id)
	if err != nil {
		return domain.Attestation{}, err
	}
	if assessment.Status != domain.StatusApproved {
		return domain.Attestation{}, ErrNotApproved
	}

	statement, err := s.build.Build(assessment, actor.GitHubUser)
	if err != nil {
		return domain.Attestation{}, err
	}
	sig, err := s.signer.Sign(ctx, statement, actor)
	if err != nil {
		return domain.Attestation{}, err
	}

	att, err := s.repo.SaveAttestation(ctx, domain.Attestation{
		AssessmentID:  id,
		StatementJSON: statement,
		Signature:     sig,
		SignedBy:      actor.GitHubUser,
		SignedEmail:   actor.Email,
		OIDCSubject:   actor.OIDCSubject,
		SigningTime:   time.Now().UTC(),
	})
	if err != nil {
		return domain.Attestation{}, err
	}
	if err := s.repo.AppendAuditLog(ctx, domain.AuditLog{ActorUserID: &actor.ID, EventType: "attestation generation", EntityType: "assessment", EntityID: fmt.Sprintf("%d", id), Payload: fmt.Sprintf("attestation=%d", att.ID)}); err != nil {
		return domain.Attestation{}, err
	}
	if err := s.repo.AppendAuditLog(ctx, domain.AuditLog{ActorUserID: &actor.ID, EventType: "signing", EntityType: "attestation", EntityID: fmt.Sprintf("%d", att.ID), Payload: actor.OIDCSubject}); err != nil {
		return domain.Attestation{}, err
	}
	return att, nil
}

func (s *Service) PublishAttestation(ctx context.Context, actor domain.User, assessmentID int64, attestationID int64, registry, ref string) error {
	assessment, err := s.repo.GetAssessmentByID(ctx, assessmentID)
	if err != nil {
		return err
	}
	if assessment.Status != domain.StatusApproved {
		return ErrNotApproved
	}

	var att domain.Attestation
	if attestationID != 0 {
		att, err = s.repo.GetAttestationByID(ctx, attestationID)
		if err != nil {
			return err
		}
	} else {
		att, err = s.GenerateAndSignAttestation(ctx, actor, assessmentID)
		if err != nil {
			return err
		}
	}
	ociRef, err := s.publish.Publish(ctx, registry, ref, att.StatementJSON)
	if err != nil {
		return err
	}
	if err := s.repo.UpdateAttestationPublication(ctx, att.ID, registry, ociRef, time.Now().UTC()); err != nil {
		return err
	}
	return s.repo.AppendAuditLog(ctx, domain.AuditLog{ActorUserID: &actor.ID, EventType: "OCI publication", EntityType: "attestation", EntityID: fmt.Sprintf("%d", att.ID), Payload: ociRef})
}
