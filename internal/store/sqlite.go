package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db    *sql.DB
	codec SecretCodec
}

func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

func NewSQLiteStore(dsn string, codec SecretCodec) (*SQLiteStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("sqlite dsn is required")
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	return &SQLiteStore{db: db, codec: codec}, nil
}

func NewSQLiteStoreWithDB(db *sql.DB, codec SecretCodec) *SQLiteStore {
	return &SQLiteStore{db: db, codec: codec}
}

func (s *SQLiteStore) AddComputer(serial, username, computerName string) (*Computer, error) {
	now := time.Now()
	var id int
	var lastCheckin time.Time
	row := s.db.QueryRow(
		"INSERT INTO computers (serial, username, computername, last_checkin) VALUES (?, ?, ?, ?) RETURNING id, last_checkin",
		serial, username, computerName, now,
	)
	if err := row.Scan(&id, &lastCheckin); err != nil {
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

func (s *SQLiteStore) UpsertComputer(serial, username, computerName string, lastCheckin time.Time) (*Computer, error) {
	var id int
	var stored time.Time
	row := s.db.QueryRow(
		"INSERT INTO computers (serial, username, computername, last_checkin) VALUES (?, ?, ?, ?) ON CONFLICT(serial) DO UPDATE SET username = excluded.username, computername = excluded.computername, last_checkin = excluded.last_checkin RETURNING id, last_checkin",
		serial, username, computerName, lastCheckin,
	)
	if err := row.Scan(&id, &stored); err != nil {
		return nil, fmt.Errorf("upsert computer: %w", err)
	}
	return &Computer{
		ID:           id,
		Serial:       serial,
		Username:     username,
		ComputerName: computerName,
		LastCheckin:  stored,
	}, nil
}

func (s *SQLiteStore) ListComputers() ([]*Computer, error) {
	rows, err := s.db.Query("SELECT id, serial, username, computername, last_checkin FROM computers ORDER BY id")
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

func (s *SQLiteStore) GetComputerByID(id int) (*Computer, error) {
	var computer Computer
	var lastCheckin sql.NullTime
	row := s.db.QueryRow("SELECT id, serial, username, computername, last_checkin FROM computers WHERE id = ?", id)
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

func (s *SQLiteStore) GetComputerBySerial(serial string) (*Computer, error) {
	var computer Computer
	var lastCheckin sql.NullTime
	row := s.db.QueryRow("SELECT id, serial, username, computername, last_checkin FROM computers WHERE lower(serial) = lower(?)", serial)
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

func (s *SQLiteStore) AddSecret(computerID int, secretType, secret string, rotationRequired bool) (*Secret, error) {
	if s.codec == nil {
		return nil, ErrMissingCodec
	}
	encrypted, err := s.codec.Encrypt(secret)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var id int
	var dateEscrowed time.Time
	row := s.db.QueryRow(
		"INSERT INTO secrets (computer_id, secret_type, secret, date_escrowed, rotation_required) VALUES (?, ?, ?, ?, ?) RETURNING id, date_escrowed",
		computerID, secretType, encrypted, now, rotationRequired,
	)
	if err := row.Scan(&id, &dateEscrowed); err != nil {
		return nil, fmt.Errorf("insert secret: %w", err)
	}
	return s.decryptSecret(&Secret{
		ID:               id,
		ComputerID:       computerID,
		SecretType:       secretType,
		Secret:           encrypted,
		DateEscrowed:     dateEscrowed,
		RotationRequired: rotationRequired,
	})
}

func (s *SQLiteStore) ListSecretsByComputer(computerID int) ([]*Secret, error) {
	rows, err := s.db.Query("SELECT id, computer_id, secret_type, secret, date_escrowed, rotation_required FROM secrets WHERE computer_id = ? ORDER BY id", computerID)
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()

	secrets := make([]*Secret, 0)
	for rows.Next() {
		secret, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		decrypted, err := s.decryptSecret(secret)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, decrypted)
	}
	return secrets, rows.Err()
}

func (s *SQLiteStore) GetSecretByID(id int) (*Secret, error) {
	row := s.db.QueryRow("SELECT id, computer_id, secret_type, secret, date_escrowed, rotation_required FROM secrets WHERE id = ?", id)
	secret, err := scanSecret(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}
	return s.decryptSecret(secret)
}

func (s *SQLiteStore) GetLatestSecretByComputerAndType(computerID int, secretType string) (*Secret, error) {
	row := s.db.QueryRow(
		"SELECT id, computer_id, secret_type, secret, date_escrowed, rotation_required FROM secrets WHERE computer_id = ? AND secret_type = ? ORDER BY date_escrowed DESC LIMIT 1",
		computerID, secretType,
	)
	secret, err := scanSecret(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get latest secret: %w", err)
	}
	return s.decryptSecret(secret)
}

func (s *SQLiteStore) AddRequest(secretID int, requestingUser, reason string, approvedBy string, approved *bool) (*Request, error) {
	now := time.Now()
	var id int
	var dateRequested time.Time
	var dateApproved sql.NullTime
	var approvedValue sql.NullBool
	if approved != nil {
		approvedValue.Valid = true
		approvedValue.Bool = *approved
		dateApproved.Valid = true
		dateApproved.Time = now
	}
	row := s.db.QueryRow(
		"INSERT INTO requests (secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, date_requested, date_approved",
		secretID, requestingUser, approvedValue, nullableString(approvedBy), reason, sql.NullString{}, now, dateApproved, true,
	)
	if err := row.Scan(&id, &dateRequested, &dateApproved); err != nil {
		return nil, fmt.Errorf("insert request: %w", err)
	}
	var approvedPtr *bool
	if approvedValue.Valid {
		value := approvedValue.Bool
		approvedPtr = &value
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

func (s *SQLiteStore) ListRequestsBySecret(secretID int) ([]*Request, error) {
	rows, err := s.db.Query("SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE secret_id = ? ORDER BY id", secretID)
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

func (s *SQLiteStore) ListOutstandingRequests() ([]*Request, error) {
	rows, err := s.db.Query("SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE current = true AND approved IS NULL ORDER BY id")
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

func (s *SQLiteStore) GetRequestByID(id int) (*Request, error) {
	row := s.db.QueryRow("SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE id = ?", id)
	request, err := scanRequest(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return request, nil
}

func (s *SQLiteStore) ApproveRequest(requestID int, approved bool, reason, approver string) (*Request, error) {
	dateApproved := time.Now()
	result, err := s.db.Exec(
		"UPDATE requests SET approved = ?, reason_for_approval = ?, auth_user = ?, date_approved = ? WHERE id = ?",
		approved, reason, approver, dateApproved, requestID,
	)
	if err != nil {
		return nil, fmt.Errorf("approve request: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("approve request: %w", err)
	}
	if affected == 0 {
		return nil, ErrNotFound
	}
	updated, err := s.GetRequestByID(requestID)
	if err != nil {
		return nil, err
	}
	if updated.DateApproved == nil {
		updated.DateApproved = &dateApproved
	}
	return updated, nil
}

func (s *SQLiteStore) AddUser(username, passwordHash string, isStaff, canApprove, localLoginEnabled, mustResetPassword bool, authSource string) (*User, error) {
	var id int
	row := s.db.QueryRow(
		"INSERT INTO users (username, password_hash, is_staff, can_approve, local_login_enabled, must_reset_password, auth_source) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
		username, nullableString(passwordHash), isStaff, canApprove, localLoginEnabled, mustResetPassword, authSource,
	)
	if err := row.Scan(&id); err != nil {
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return &User{
		ID:                id,
		Username:          username,
		PasswordHash:      passwordHash,
		IsStaff:           isStaff,
		CanApprove:        canApprove,
		LocalLoginEnabled: localLoginEnabled,
		MustResetPassword: mustResetPassword,
		AuthSource:        authSource,
	}, nil
}

func (s *SQLiteStore) GetUserByUsername(username string) (*User, error) {
	var user User
	var passwordHash sql.NullString
	row := s.db.QueryRow("SELECT id, username, password_hash, is_staff, can_approve, local_login_enabled, must_reset_password, auth_source FROM users WHERE lower(username) = lower(?)", username)
	if err := row.Scan(&user.ID, &user.Username, &passwordHash, &user.IsStaff, &user.CanApprove, &user.LocalLoginEnabled, &user.MustResetPassword, &user.AuthSource); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user by username: %w", err)
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	return &user, nil
}

func (s *SQLiteStore) ListUsers() ([]*User, error) {
	rows, err := s.db.Query("SELECT id, username, password_hash, is_staff, can_approve, local_login_enabled, must_reset_password, auth_source FROM users ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	users := make([]*User, 0)
	for rows.Next() {
		var user User
		var passwordHash sql.NullString
		if err := rows.Scan(&user.ID, &user.Username, &passwordHash, &user.IsStaff, &user.CanApprove, &user.LocalLoginEnabled, &user.MustResetPassword, &user.AuthSource); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if passwordHash.Valid {
			user.PasswordHash = passwordHash.String
		}
		users = append(users, &user)
	}
	return users, rows.Err()
}

func (s *SQLiteStore) GetUserByID(id int) (*User, error) {
	var user User
	var passwordHash sql.NullString
	row := s.db.QueryRow("SELECT id, username, password_hash, is_staff, can_approve, local_login_enabled, must_reset_password, auth_source FROM users WHERE id = ?", id)
	if err := row.Scan(&user.ID, &user.Username, &passwordHash, &user.IsStaff, &user.CanApprove, &user.LocalLoginEnabled, &user.MustResetPassword, &user.AuthSource); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	return &user, nil
}

func (s *SQLiteStore) UpdateUser(id int, username string, isStaff, canApprove, localLoginEnabled, mustResetPassword bool, authSource string) (*User, error) {
	var user User
	var passwordHash sql.NullString
	row := s.db.QueryRow(
		"UPDATE users SET username = ?, is_staff = ?, can_approve = ?, local_login_enabled = ?, must_reset_password = ?, auth_source = ? WHERE id = ? RETURNING id, username, password_hash, is_staff, can_approve, local_login_enabled, must_reset_password, auth_source",
		username, isStaff, canApprove, localLoginEnabled, mustResetPassword, authSource, id,
	)
	if err := row.Scan(&user.ID, &user.Username, &passwordHash, &user.IsStaff, &user.CanApprove, &user.LocalLoginEnabled, &user.MustResetPassword, &user.AuthSource); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("update user: %w", err)
	}
	if passwordHash.Valid {
		user.PasswordHash = passwordHash.String
	}
	return &user, nil
}

func (s *SQLiteStore) UpdateUserPassword(id int, passwordHash string, mustResetPassword bool) (*User, error) {
	var user User
	var hash sql.NullString
	row := s.db.QueryRow(
		"UPDATE users SET password_hash = ?, must_reset_password = ?, local_login_enabled = CASE WHEN ? IS NULL THEN local_login_enabled ELSE 1 END WHERE id = ? RETURNING id, username, password_hash, is_staff, can_approve, local_login_enabled, must_reset_password, auth_source",
		nullableString(passwordHash), mustResetPassword, nullableString(passwordHash), id,
	)
	if err := row.Scan(&user.ID, &user.Username, &hash, &user.IsStaff, &user.CanApprove, &user.LocalLoginEnabled, &user.MustResetPassword, &user.AuthSource); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("update user password: %w", err)
	}
	if hash.Valid {
		user.PasswordHash = hash.String
	}
	return &user, nil
}

func (s *SQLiteStore) DeleteUser(id int) error {
	result, err := s.db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) CleanupRequests(approvedBefore time.Time) (int, error) {
	result, err := s.db.Exec(
		"UPDATE requests SET current = 0 WHERE current = 1 AND approved IS NOT NULL AND date_approved < ?",
		approvedBefore,
	)
	if err != nil {
		return 0, fmt.Errorf("cleanup requests: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cleanup requests: %w", err)
	}
	return int(affected), nil
}

func (s *SQLiteStore) SetSecretRotationRequired(secretID int, rotationRequired bool) (*Secret, error) {
	result, err := s.db.Exec(
		"UPDATE secrets SET rotation_required = ? WHERE id = ?",
		rotationRequired, secretID,
	)
	if err != nil {
		return nil, fmt.Errorf("update secret rotation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("update secret rotation: %w", err)
	}
	if affected == 0 {
		return nil, ErrNotFound
	}
	return s.GetSecretByID(secretID)
}

func (s *SQLiteStore) decryptSecret(secret *Secret) (*Secret, error) {
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

func scanSecret(row scanner) (*Secret, error) {
	var secret Secret
	var rotation int
	if err := row.Scan(&secret.ID, &secret.ComputerID, &secret.SecretType, &secret.Secret, &secret.DateEscrowed, &rotation); err != nil {
		return nil, err
	}
	secret.RotationRequired = rotation != 0
	return &secret, nil
}
