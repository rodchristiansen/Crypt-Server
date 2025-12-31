package store

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresStoreAddComputer(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := NewPostgresStoreWithDB(db, testCodec(t))
	lastCheckin := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(
		"INSERT INTO computers (serial, username, computername, last_checkin) VALUES ($1, $2, $3, NOW()) RETURNING id, last_checkin",
	)).WithArgs("SERIAL", "user", "Mac").WillReturnRows(sqlmock.NewRows([]string{"id", "last_checkin"}).AddRow(1, lastCheckin))

	computer, err := store.AddComputer("SERIAL", "user", "Mac")
	require.NoError(t, err)
	require.Equal(t, 1, computer.ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreListComputers(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := NewPostgresStoreWithDB(db, testCodec(t))
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, serial, username, computername, last_checkin FROM computers ORDER BY id",
	)).WillReturnRows(sqlmock.NewRows([]string{"id", "serial", "username", "computername", "last_checkin"}).AddRow(1, "SERIAL", "user", "Mac", now))

	computers, err := store.ListComputers()
	require.NoError(t, err)
	require.Len(t, computers, 1)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreGetComputerByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := NewPostgresStoreWithDB(db, testCodec(t))
	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, serial, username, computername, last_checkin FROM computers WHERE id = $1",
	)).WithArgs(1).WillReturnRows(sqlmock.NewRows([]string{"id", "serial", "username", "computername", "last_checkin"}).AddRow(1, "SERIAL", "user", "Mac", time.Now()))

	computer, err := store.GetComputerByID(1)
	require.NoError(t, err)
	require.Equal(t, "SERIAL", computer.Serial)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreAddSecret(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := NewPostgresStoreWithDB(db, testCodec(t))
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(
		"INSERT INTO secrets (computer_id, secret_type, secret, date_escrowed, rotation_required) VALUES ($1, $2, $3, NOW(), $4) RETURNING id, date_escrowed",
	)).WithArgs(1, "password", sqlmock.AnyArg(), false).WillReturnRows(sqlmock.NewRows([]string{"id", "date_escrowed"}).AddRow(5, now))

	secret, err := store.AddSecret(1, "password", "secret", false)
	require.NoError(t, err)
	require.Equal(t, 5, secret.ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreAddRequestAndApprove(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := NewPostgresStoreWithDB(db, testCodec(t))
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(
		"INSERT INTO requests (secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current) VALUES ($1, $2, $3, $4, $5, $6, NOW(), CASE WHEN $3 IS NULL THEN NULL ELSE NOW() END, true) RETURNING id, date_requested, date_approved",
	)).WithArgs(9, "user", sqlmock.AnyArg(), sqlmock.AnyArg(), "reason", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"id", "date_requested", "date_approved"}).AddRow(3, now, nil))

	request, err := store.AddRequest(9, "user", "reason", "", nil)
	require.NoError(t, err)
	require.Equal(t, 3, request.ID)

	mock.ExpectQuery(regexp.QuoteMeta(
		"UPDATE requests SET approved = $1, reason_for_approval = $2, auth_user = $3, date_approved = NOW() WHERE id = $4 RETURNING date_approved",
	)).WithArgs(true, "ok", "admin", 3).WillReturnRows(sqlmock.NewRows([]string{"date_approved"}).AddRow(now))

	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE id = $1",
	)).WithArgs(3).WillReturnRows(sqlmock.NewRows([]string{"id", "secret_id", "requesting_user", "approved", "auth_user", "reason_for_request", "reason_for_approval", "date_requested", "date_approved", "current"}).AddRow(3, 9, "user", true, "admin", "reason", "ok", now, now, true))

	approved, err := store.ApproveRequest(3, true, "ok", "admin")
	require.NoError(t, err)
	require.NotNil(t, approved.Approved)
	require.True(t, *approved.Approved)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreGetSecretAndRequests(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	codec := testCodec(t)
	store := NewPostgresStoreWithDB(db, codec)
	now := time.Now()

	encryptedSecret, err := codec.Encrypt("secret")
	require.NoError(t, err)
	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, computer_id, secret_type, secret, date_escrowed, rotation_required FROM secrets WHERE id = $1",
	)).WithArgs(2).WillReturnRows(sqlmock.NewRows([]string{"id", "computer_id", "secret_type", "secret", "date_escrowed", "rotation_required"}).AddRow(2, 1, "password", encryptedSecret, now, false))

	secret, err := store.GetSecretByID(2)
	require.NoError(t, err)
	require.Equal(t, "password", secret.SecretType)
	require.Equal(t, "secret", secret.Secret)

	encryptedSecret2, err := codec.Encrypt("secret")
	require.NoError(t, err)
	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, computer_id, secret_type, secret, date_escrowed, rotation_required FROM secrets WHERE computer_id = $1 ORDER BY id",
	)).WithArgs(1).WillReturnRows(sqlmock.NewRows([]string{"id", "computer_id", "secret_type", "secret", "date_escrowed", "rotation_required"}).AddRow(2, 1, "password", encryptedSecret2, now, false))

	secrets, err := store.ListSecretsByComputer(1)
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	require.Equal(t, "secret", secrets[0].Secret)

	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE secret_id = $1 ORDER BY id",
	)).WithArgs(2).WillReturnRows(sqlmock.NewRows([]string{"id", "secret_id", "requesting_user", "approved", "auth_user", "reason_for_request", "reason_for_approval", "date_requested", "date_approved", "current"}).AddRow(5, 2, "user", nil, nil, "reason", nil, now, nil, true))

	requests, err := store.ListRequestsBySecret(2)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE current = true AND approved IS NULL ORDER BY id",
	)).WillReturnRows(sqlmock.NewRows([]string{"id", "secret_id", "requesting_user", "approved", "auth_user", "reason_for_request", "reason_for_approval", "date_requested", "date_approved", "current"}).AddRow(5, 2, "user", nil, nil, "reason", nil, now, nil, true))

	outstanding, err := store.ListOutstandingRequests()
	require.NoError(t, err)
	require.Len(t, outstanding, 1)

	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, secret_id, requesting_user, approved, auth_user, reason_for_request, reason_for_approval, date_requested, date_approved, current FROM requests WHERE id = $1",
	)).WithArgs(5).WillReturnRows(sqlmock.NewRows([]string{"id", "secret_id", "requesting_user", "approved", "auth_user", "reason_for_request", "reason_for_approval", "date_requested", "date_approved", "current"}).AddRow(5, 2, "user", nil, nil, "reason", nil, now, nil, true))

	request, err := store.GetRequestByID(5)
	require.NoError(t, err)
	require.Equal(t, 2, request.SecretID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreUserLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	store := NewPostgresStoreWithDB(db, testCodec(t))
	mock.ExpectQuery(regexp.QuoteMeta(
		"INSERT INTO users (username, password_hash, is_staff, can_approve, has_usable_password) VALUES ($1, $2, $3, $4, $5) RETURNING id",
	)).WithArgs("admin", sqlmock.AnyArg(), true, true, true).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(7))

	user, err := store.AddUser("admin", "hash", true, true, true)
	require.NoError(t, err)
	require.Equal(t, 7, user.ID)

	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, username, password_hash, is_staff, can_approve, has_usable_password FROM users WHERE lower(username) = lower($1)",
	)).WithArgs("admin").WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password_hash", "is_staff", "can_approve", "has_usable_password"}).AddRow(7, "admin", "hash", true, true, true))

	loaded, err := store.GetUserByUsername("admin")
	require.NoError(t, err)
	require.Equal(t, "admin", loaded.Username)

	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, username, password_hash, is_staff, can_approve, has_usable_password FROM users WHERE id = $1",
	)).WithArgs(7).WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password_hash", "is_staff", "can_approve", "has_usable_password"}).AddRow(7, "admin", "hash", true, true, true))

	byID, err := store.GetUserByID(7)
	require.NoError(t, err)
	require.Equal(t, "admin", byID.Username)

	mock.ExpectQuery(regexp.QuoteMeta(
		"UPDATE users SET username = $1, is_staff = $2, can_approve = $3, has_usable_password = $4 WHERE id = $5 RETURNING id, username, password_hash, is_staff, can_approve, has_usable_password",
	)).WithArgs("updated", false, false, false, 7).WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password_hash", "is_staff", "can_approve", "has_usable_password"}).AddRow(7, "updated", "hash", false, false, false))

	updated, err := store.UpdateUser(7, "updated", false, false, false)
	require.NoError(t, err)
	require.Equal(t, "updated", updated.Username)

	mock.ExpectQuery(regexp.QuoteMeta(
		"UPDATE users SET password_hash = $1, has_usable_password = $2 WHERE id = $3 RETURNING id, username, password_hash, is_staff, can_approve, has_usable_password",
	)).WithArgs(sqlmock.AnyArg(), true, 7).WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password_hash", "is_staff", "can_approve", "has_usable_password"}).AddRow(7, "updated", "newhash", false, false, true))

	passwordUpdated, err := store.UpdateUserPassword(7, "newhash", true)
	require.NoError(t, err)
	require.Equal(t, "newhash", passwordUpdated.PasswordHash)

	mock.ExpectQuery(regexp.QuoteMeta(
		"SELECT id, username, password_hash, is_staff, can_approve, has_usable_password FROM users ORDER BY id",
	)).WillReturnRows(sqlmock.NewRows([]string{"id", "username", "password_hash", "is_staff", "can_approve", "has_usable_password"}).
		AddRow(7, "admin", "hash", true, true, true).
		AddRow(8, "viewer", nil, false, false, false))

	users, err := store.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 2)

	mock.ExpectExec(regexp.QuoteMeta(
		"DELETE FROM users WHERE id = $1",
	)).WithArgs(7).WillReturnResult(sqlmock.NewResult(0, 1))

	require.NoError(t, store.DeleteUser(7))
	require.NoError(t, mock.ExpectationsWereMet())
}
