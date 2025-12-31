package store

import "time"

type Computer struct {
	ID           int
	Serial       string
	Username     string
	ComputerName string
	LastCheckin  time.Time
}

type Secret struct {
	ID               int
	ComputerID       int
	SecretType       string
	Secret           string
	DateEscrowed     time.Time
	RotationRequired bool
}

type Request struct {
	ID                int
	SecretID          int
	RequestingUser    string
	Approved          *bool
	AuthUser          string
	ReasonForRequest  string
	ReasonForApproval string
	DateRequested     time.Time
	DateApproved      *time.Time
	Current           bool
}

type User struct {
	ID                int
	Username          string
	PasswordHash      string
	IsStaff           bool
	CanApprove        bool
	HasUsablePassword bool
}
