// Package session provides an in-memory store for active assessment wizard state.
// No persistence: state exists only for the duration of a single assessment run.
package session

import (
	"sync"

	"github.com/h3ow3d/special-dollop/internal/domain"
)

// Store holds assessment wizard sessions in memory.
type Store struct {
	mu   sync.RWMutex
	data map[string]*domain.AssessmentState
}

// NewStore creates an empty in-memory session store.
func NewStore() *Store {
	return &Store{data: make(map[string]*domain.AssessmentState)}
}

// Set creates or replaces the assessment state for the given ID.
func (s *Store) Set(state *domain.AssessmentState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state.ID] = state
}

// Get retrieves the assessment state for the given ID.
func (s *Store) Get(id string) (*domain.AssessmentState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.data[id]
	return st, ok
}

// Delete removes the assessment state for the given ID.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
}
