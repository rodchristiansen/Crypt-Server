package store

import (
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")
var ErrMissingCodec = errors.New("secret codec is required")

type SecretCodec interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

type Store interface {
	AddComputer(serial, username, computerName string) (*Computer, error)
	UpsertComputer(serial, username, computerName string, lastCheckin time.Time) (*Computer, error)
	ListComputers() ([]*Computer, error)
	GetComputerByID(id int) (*Computer, error)
	GetComputerBySerial(serial string) (*Computer, error)
	AddSecret(computerID int, secretType, secret string, rotationRequired bool) (*Secret, error)
	ListSecretsByComputer(computerID int) ([]*Secret, error)
	GetSecretByID(id int) (*Secret, error)
	GetLatestSecretByComputerAndType(computerID int, secretType string) (*Secret, error)
	AddRequest(secretID int, requestingUser, reason string, approvedBy string, approved *bool) (*Request, error)
	ListRequestsBySecret(secretID int) ([]*Request, error)
	ListOutstandingRequests() ([]*Request, error)
	GetRequestByID(id int) (*Request, error)
	ApproveRequest(requestID int, approved bool, reason, approver string) (*Request, error)
	AddUser(username, passwordHash string, isStaff, canApprove, localLoginEnabled, mustResetPassword bool, authSource string) (*User, error)
	GetUserByUsername(username string) (*User, error)
	ListUsers() ([]*User, error)
	GetUserByID(id int) (*User, error)
	UpdateUser(id int, username string, isStaff, canApprove, localLoginEnabled, mustResetPassword bool, authSource string) (*User, error)
	UpdateUserPassword(id int, passwordHash string, mustResetPassword bool) (*User, error)
	DeleteUser(id int) error
	CleanupRequests(approvedBefore time.Time) (int, error)
	SetSecretRotationRequired(secretID int, rotationRequired bool) (*Secret, error)
	AddAuditEvent(actor, targetUser, action, reason, ipAddress string) (*AuditEvent, error)
	ListAuditEvents() ([]*AuditEvent, error)
}
