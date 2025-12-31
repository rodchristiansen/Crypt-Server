package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(dbURL string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

func NewPostgresStoreWithDB(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) AddComputer(serial, username, computerName string) (*Computer, error) {
	var id int
	var lastCheckin time.Time
	err := s.db.QueryRow(
		`INSERT INTO computers (serial, username, computername, last_checkin)
		 VALUES ($1, $2, $3, NOW())
		 RETURNING id, last_checkin`,
		serial, username, computerName,
	).Scan(&id, &lastCheckin)
	if err != nil {
		return nil, fmt.Errorf("insert computer: %w", err)
	}
	return &Computer{
		ID:           id,
		Serial:       serial,
		Username:     username,
		ComputerName: computerName,
		LastCheckin:  lastCheckin,
	}, nil
}

func (s *PostgresStore) ListComputers() ([]*Computer, error) {
	rows, err := s.db.Query(`SELECT id, serial, username, computername, last_checkin FROM computers ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list computers: %w", err)
	}
	defer rows.Close()

	computers := make([]*Computer, 0)
	for rows.Next() {
		var computer Computer
		var lastCheckin sql.NullTime
		if err := rows.Scan(&computer.ID, &computer.Serial, &computer.Username, &computer.ComputerName, &lastCheckin); err != nil {
			return nil, fmt.Errorf("scan computer: %w", err)
		}
		if lastCheckin.Valid {
			computer.LastCheckin = lastCheckin.Time
		}
		computers = append(computers, &computer)
	}
	return computers, rows.Err()
}

func (s *PostgresStore) GetComputerByID(id int) (*Computer, error) {
	var computer Computer
	var lastCheckin sql.NullTime
	row := s.db.QueryRow(`SELECT id, serial, username, computername, last_checkin FROM computers WHERE id = $1`, id)
	if err := row.Scan(&computer.ID, &computer.Serial, &computer.Username, &computer.ComputerName, &lastCheckin); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get computer by id: %w", err)
	}
	if lastCheckin.Valid {
		computer.LastCheckin = lastCheckin.Time
	}
	return &computer, nil
}

func (s *PostgresStore) GetComputerBySerial(serial string) (*Computer, error) {
	var computer Computer
	var lastCheckin sql.NullTime
	row := s.db.QueryRow(`SELECT id, serial, username, computername, last_checkin FROM computers WHERE lower(serial) = lower($1)`, serial)
	if err := row.Scan(&computer.ID, &computer.Serial, &computer.Username, &computer.ComputerName, &lastCheckin); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get computer by serial: %w", err)
	}
	if lastCheckin.Valid {
		computer.LastCheckin = lastCheckin.Time
	}
	return &computer, nil
}

func (s *PostgresStore) AddSecret(computerID int, secretType, secret string, rotationRequired bool) (*Secret, error) {
	var id int
	var dateEscrowed time.Time
	row := s.db.QueryRow(
		`INSERT INTO secrets (computer_id, secret_type, secret, date_escrowed, rotation_required)
		 VALUES ($1, $2, $3, NOW(), $4)
		 RETURNING id, date_escrowed`,
		computerID, secretType, secret, rotationRequired,
	)
	if err := row.Scan(&id, &dateEscrowed); err != nil {
		return nil, fmt.Errorf("insert secret: %w", err)
	}

	return &Secret{
		ID:               id,
		ComputerID:       computerID,
		SecretType:       secretType,
		Secret:           secret,
		DateEscrowed:     dateEscrowed,
		RotationRequired: rotationRequired,
	}, nil
}

func (s *PostgresStore) ListSecretsByComputer(computerID int) ([]*Secret, error) {
	rows, err := s.db.Query(`SELECT id, computer_id, secret_type, secret, date_escrowed, rotation_required FROM secrets WHERE computer_id = $1 ORDER BY id`, computerID)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()

	secrets := make([]*Secret, 0)
	for rows.Next() {
		var secret Secret
		if err := rows.Scan(&secret.ID, &secret.ComputerID, &secret.SecretType, &secret.Secret, &secret.DateEscrowed, &secret.RotationRequired); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		secrets = append(secrets, &secret)
	}
	return secrets, rows.Err()
}

func (s *PostgresStore) GetSecretByID(id int) (*Secret, error) {
	var secret Secret
	row := s.db.QueryRow(`SELECT id, computer_id, secret_type, secret, date_escrowed, rotation_required FROM secrets WHERE id = $1`, id)
	if err := row.Scan(&secret.ID, &secret.ComputerID, &secret.SecretType, &secret.Secret, &secret.DateEscrowed, &secret.RotationRequired); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}
	return &secret, nil
}

func (s *PostgresStore) AddRequest(secretID int, requestingUser, reason string, approvedBy string, approved *bool) (*Request, error) {
	var id int
	var dateRequested time.Time
	var dateApproved sql.NullTime
	var approvedValue sql.NullBool
	if approved != nil {
		approvedValue.Valid = true
		approvedValue.Bool = *approved
	}
	row := s.db.QueryRow(
		`INSERT INTO requests (secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW(), CASE WHEN $3 IS NULL THEN NULL ELSE NOW() END, true)
		 RETURNING id, date_requested, date_approved`,
		secretID, requestingUser, approvedValue, nullableString(approvedBy), reason, sql.NullString{},
	)
	if err := row.Scan(&id, &dateRequested, &dateApproved); err != nil {
		return nil, fmt.Errorf("insert request: %w", err)
	}

	var approvedPtr *bool
	if approvedValue.Valid {
		approvedPtr = &approvedValue.Bool
	}
	var dateApprovedPtr *time.Time
	if dateApproved.Valid {
		dateApprovedPtr = &dateApproved.Time
	}

	return &Request{
		ID:                id,
		SecretID:          secretID,
		RequestingUser:    requestingUser,
		Approved:          approvedPtr,
		AuthUser:          approvedBy,
		ReasonForRequest:  reason,
		ReasonForApproval: "",
		DateRequested:     dateRequested,
		DateApproved:      dateApprovedPtr,
		Current:           true,
	}, nil
}

func (s *PostgresStore) ListRequestsBySecret(secretID int) ([]*Request, error) {
	rows, err := s.db.Query(`SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE secret_id = $1 ORDER BY id`, secretID)
	if err != nil {
		return nil, fmt.Errorf("list requests: %w", err)
	}
	defer rows.Close()

	requests := make([]*Request, 0)
	for rows.Next() {
		request, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (s *PostgresStore) ListOutstandingRequests() ([]*Request, error) {
	rows, err := s.db.Query(`SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE current = true AND approved IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list outstanding requests: %w", err)
	}
	defer rows.Close()

	requests := make([]*Request, 0)
	for rows.Next() {
		request, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

func (s *PostgresStore) GetRequestByID(id int) (*Request, error) {
	row := s.db.QueryRow(`SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE id = $1`, id)
	request, err := scanRequest(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return request, nil
}

func (s *PostgresStore) ApproveRequest(requestID int, approved bool, reason, approver string) (*Request, error) {
	var dateApproved time.Time
	row := s.db.QueryRow(
		`UPDATE requests
		 SET approved = $1, reason_for_approval = $2, auth_user = $3, date_approved = NOW()
		 WHERE id = $4
		 RETURNING date_approved`,
		approved, reason, approver, requestID,
	)
	if err := row.Scan(&dateApproved); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("approve request: %w", err)
	}
	updated, err := s.GetRequestByID(requestID)
	if err != nil {
		return nil, err
	}
	updated.DateApproved = &dateApproved
	return updated, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRequest(row scanner) (*Request, error) {
	var request Request
	var approved sql.NullBool
	var authUser sql.NullString
	var reasonApproval sql.NullString
	var dateApproved sql.NullTime
	if err := row.Scan(
		&request.ID,
		&request.SecretID,
		&request.RequestingUser,
		&approved,
		&authUser,
		&request.ReasonForRequest,
		&reasonApproval,
		&request.DateRequested,
		&dateApproved,
		&request.Current,
	); err != nil {
		return nil, err
	}

	if approved.Valid {
		value := approved.Bool
		request.Approved = &value
	}
	if authUser.Valid {
		request.AuthUser = authUser.String
	}
	if reasonApproval.Valid {
		request.ReasonForApproval = reasonApproval.String
	}
	if dateApproved.Valid {
		request.DateApproved = &dateApproved.Time
	}

	return &request, nil
}

func nullableString(value string) sql.NullString {
	if strings.TrimSpace(value) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}
