package store

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryStore keeps data in memory while we build out the persistence layer.
type MemoryStore struct {
	mu             sync.RWMutex
	nextComputerID int
	nextSecretID   int
	nextRequestID  int
	nextUserID     int
	computers      map[int]*Computer
	secrets        map[int]*Secret
	requests       map[int]*Request
	users          map[int]*User
	codec          SecretCodec
}

func NewMemoryStore(codec SecretCodec) *MemoryStore {
	return &MemoryStore{
		nextComputerID: 1,
		nextSecretID:   1,
		nextRequestID:  1,
		nextUserID:     1,
		computers:      make(map[int]*Computer),
		secrets:        make(map[int]*Secret),
		requests:       make(map[int]*Request),
		users:          make(map[int]*User),
		codec:          codec,
	}
}

func (s *MemoryStore) AddComputer(serial, username, computerName string) (*Computer, error) {
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
	return computer, nil
}

func (s *MemoryStore) ListComputers() ([]*Computer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	computers := make([]*Computer, 0, len(s.computers))
	for _, computer := range s.computers {
		computers = append(computers, computer)
	}
	sort.Slice(computers, func(i, j int) bool {
		return computers[i].ID < computers[j].ID
	})
	return computers, nil
}

func (s *MemoryStore) GetComputerByID(id int) (*Computer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	computer, ok := s.computers[id]
	if !ok {
		return nil, ErrNotFound
	}
	return computer, nil
}

func (s *MemoryStore) GetComputerBySerial(serial string) (*Computer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, computer := range s.computers {
		if strings.EqualFold(computer.Serial, serial) {
			return computer, nil
		}
	}
	return nil, ErrNotFound
}

func (s *MemoryStore) AddSecret(computerID int, secretType, secret string, rotationRequired bool) (*Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.computers[computerID]; !ok {
		return nil, ErrNotFound
	}
	if s.codec == nil {
		return nil, ErrMissingCodec
	}
	encrypted, err := s.codec.Encrypt(secret)
	if err != nil {
		return nil, err
	}
	entry := &Secret{
		ID:               s.nextSecretID,
		ComputerID:       computerID,
		SecretType:       secretType,
		Secret:           encrypted,
		DateEscrowed:     time.Now(),
		RotationRequired: rotationRequired,
	}
	s.nextSecretID++
	s.secrets[entry.ID] = entry
	return s.decryptSecret(entry)
}

func (s *MemoryStore) ListSecretsByComputer(computerID int) ([]*Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, ok := s.computers[computerID]; !ok {
		return nil, ErrNotFound
	}
	secrets := make([]*Secret, 0)
	for _, secret := range s.secrets {
		if secret.ComputerID == computerID {
			decrypted, err := s.decryptSecret(secret)
			if err != nil {
				return nil, err
			}
			secrets = append(secrets, decrypted)
		}
	}
	sort.Slice(secrets, func(i, j int) bool {
		return secrets[i].ID < secrets[j].ID
	})
	return secrets, nil
}

func (s *MemoryStore) GetSecretByID(id int) (*Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secret, ok := s.secrets[id]
	if !ok {
		return nil, ErrNotFound
	}
	return s.decryptSecret(secret)
}

func (s *MemoryStore) AddRequest(secretID int, requestingUser, reason string, approvedBy string, approved *bool) (*Request, error) {
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

func (s *MemoryStore) ListRequestsBySecret(secretID int) ([]*Request, error) {
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

func (s *MemoryStore) ListOutstandingRequests() ([]*Request, error) {
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
	return requests, nil
}

func (s *MemoryStore) GetRequestByID(id int) (*Request, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	request, ok := s.requests[id]
	if !ok {
		return nil, ErrNotFound
	}
	return request, nil
}

func (s *MemoryStore) ApproveRequest(requestID int, approved bool, reason, approver string) (*Request, error) {
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

func (s *MemoryStore) AddUser(username, passwordHash string, isStaff, canApprove, hasUsablePassword bool) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.users {
		if strings.EqualFold(existing.Username, username) {
			return nil, errors.New("username already exists")
		}
	}
	user := &User{
		ID:                s.nextUserID,
		Username:          username,
		PasswordHash:      passwordHash,
		IsStaff:           isStaff,
		CanApprove:        canApprove,
		HasUsablePassword: hasUsablePassword,
	}
	s.nextUserID++
	s.users[user.ID] = user
	return user, nil
}

func (s *MemoryStore) GetUserByUsername(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if strings.EqualFold(user.Username, username) {
			return user, nil
		}
	}
	return nil, ErrNotFound
}

func (s *MemoryStore) ListUsers() ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].ID < users[j].ID
	})
	return users, nil
}

func (s *MemoryStore) GetUserByID(id int) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return user, nil
}

func (s *MemoryStore) UpdateUser(id int, username string, isStaff, canApprove, hasUsablePassword bool) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	for _, existing := range s.users {
		if existing.ID != id && strings.EqualFold(existing.Username, username) {
			return nil, errors.New("username already exists")
		}
	}
	user.Username = username
	user.IsStaff = isStaff
	user.CanApprove = canApprove
	user.HasUsablePassword = hasUsablePassword
	return user, nil
}

func (s *MemoryStore) UpdateUserPassword(id int, passwordHash string, hasUsablePassword bool) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	user.PasswordHash = passwordHash
	user.HasUsablePassword = hasUsablePassword
	return user, nil
}

func (s *MemoryStore) DeleteUser(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[id]; !ok {
		return ErrNotFound
	}
	delete(s.users, id)
	return nil
}

func (s *MemoryStore) decryptSecret(secret *Secret) (*Secret, error) {
	if s.codec == nil {
		return nil, ErrMissingCodec
	}
	plaintext, err := s.codec.Decrypt(secret.Secret)
	if err != nil {
		return nil, err
	}
	clone := *secret
	clone.Secret = plaintext
	return &clone, nil
}
