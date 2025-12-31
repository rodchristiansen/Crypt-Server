package store

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrNotFound = errors.New("not found")

// Store keeps data in memory while we build out the persistence layer.
type Store struct {
	mu             sync.RWMutex
	nextComputerID int
	nextSecretID   int
	nextRequestID  int
	computers      map[int]*Computer
	secrets        map[int]*Secret
	requests       map[int]*Request
}

func NewStore() *Store {
	return &Store{
		nextComputerID: 1,
		nextSecretID:   1,
		nextRequestID:  1,
		computers:      make(map[int]*Computer),
		secrets:        make(map[int]*Secret),
		requests:       make(map[int]*Request),
	}
}

func (s *Store) AddComputer(serial, username, computerName string) *Computer {
	s.mu.Lock()
	defer s.mu.Unlock()

	computer := &Computer{
		ID:           s.nextComputerID,
		Serial:       serial,
		Username:     username,
		ComputerName: computerName,
		LastCheckin:  time.Now(),
	}
	s.nextComputerID++
	s.computers[computer.ID] = computer
	return computer
}

func (s *Store) ListComputers() []*Computer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	computers := make([]*Computer, 0, len(s.computers))
	for _, computer := range s.computers {
		computers = append(computers, computer)
	}
	sort.Slice(computers, func(i, j int) bool {
		return computers[i].ID < computers[j].ID
	})
	return computers
}

func (s *Store) GetComputerByID(id int) (*Computer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	computer, ok := s.computers[id]
	if !ok {
		return nil, ErrNotFound
	}
	return computer, nil
}

func (s *Store) GetComputerBySerial(serial string) (*Computer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, computer := range s.computers {
		if strings.EqualFold(computer.Serial, serial) {
			return computer, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) AddSecret(computerID int, secretType, secret string, rotationRequired bool) (*Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.computers[computerID]; !ok {
		return nil, ErrNotFound
	}
	entry := &Secret{
		ID:               s.nextSecretID,
		ComputerID:       computerID,
		SecretType:       secretType,
		Secret:           secret,
		DateEscrowed:     time.Now(),
		RotationRequired: rotationRequired,
	}
	s.nextSecretID++
	s.secrets[entry.ID] = entry
	return entry, nil
}

func (s *Store) ListSecretsByComputer(computerID int) ([]*Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.computers[computerID]; !ok {
		return nil, ErrNotFound
	}
	secrets := make([]*Secret, 0)
	for _, secret := range s.secrets {
		if secret.ComputerID == computerID {
			secrets = append(secrets, secret)
		}
	}
	sort.Slice(secrets, func(i, j int) bool {
		return secrets[i].ID < secrets[j].ID
	})
	return secrets, nil
}

func (s *Store) GetSecretByID(id int) (*Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secret, ok := s.secrets[id]
	if !ok {
		return nil, ErrNotFound
	}
	return secret, nil
}

func (s *Store) AddRequest(secretID int, requestingUser, reason string, approvedBy string, approved *bool) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.secrets[secretID]; !ok {
		return nil, ErrNotFound
	}
	request := &Request{
		ID:               s.nextRequestID,
		SecretID:         secretID,
		RequestingUser:   requestingUser,
		ReasonForRequest: reason,
		Approved:         approved,
		AuthUser:         approvedBy,
		DateRequested:    time.Now(),
		Current:          true,
	}
	if approved != nil {
		now := time.Now()
		request.DateApproved = &now
	}

	s.nextRequestID++
	s.requests[request.ID] = request
	return request, nil
}

func (s *Store) ListRequestsBySecret(secretID int) ([]*Request, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.secrets[secretID]; !ok {
		return nil, ErrNotFound
	}
	requests := make([]*Request, 0)
	for _, request := range s.requests {
		if request.SecretID == secretID {
			requests = append(requests, request)
		}
	}
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].ID < requests[j].ID
	})
	return requests, nil
}

func (s *Store) ListOutstandingRequests() []*Request {
	s.mu.RLock()
	defer s.mu.RUnlock()

	requests := make([]*Request, 0)
	for _, request := range s.requests {
		if request.Current && request.Approved == nil {
			requests = append(requests, request)
		}
	}
	sort.Slice(requests, func(i, j int) bool {
		return requests[i].ID < requests[j].ID
	})
	return requests
}

func (s *Store) GetRequestByID(id int) (*Request, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	request, ok := s.requests[id]
	if !ok {
		return nil, ErrNotFound
	}
	return request, nil
}

func (s *Store) ApproveRequest(requestID int, approved bool, reason, approver string) (*Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	request, ok := s.requests[requestID]
	if !ok {
		return nil, ErrNotFound
	}
	request.Approved = &approved
	request.ReasonForApproval = reason
	request.AuthUser = approver
	now := time.Now()
	request.DateApproved = &now
	return request, nil
}
