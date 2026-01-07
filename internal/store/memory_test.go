package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMemoryStoreComputerLifecycle(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	computer, err := store.AddComputer("SERIAL1", "user1", "MacBook")
	require.NoError(t, err)
	require.NotZero(t, computer.ID)

	list, err := store.ListComputers()
	require.NoError(t, err)
	require.Len(t, list, 1)

	byID, err := store.GetComputerByID(computer.ID)
	require.NoError(t, err)
	require.Equal(t, "SERIAL1", byID.Serial)

	bySerial, err := store.GetComputerBySerial("serial1")
	require.NoError(t, err)
	require.Equal(t, computer.ID, bySerial.ID)
}

func TestMemoryStoreSecretAndRequestLifecycle(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	computer, err := store.AddComputer("SERIAL2", "user2", "iMac")
	require.NoError(t, err)

	secret, err := store.AddSecret(computer.ID, "recovery_key", "secret-value", false)
	require.NoError(t, err)
	require.NotEqual(t, "secret-value", store.secrets[secret.ID].Secret)

	secrets, err := store.ListSecretsByComputer(computer.ID)
	require.NoError(t, err)
	require.Len(t, secrets, 1)

	byID, err := store.GetSecretByID(secret.ID)
	require.NoError(t, err)
	require.Equal(t, "secret-value", byID.Secret)

	req, err := store.AddRequest(secret.ID, "user2", "Need access", "", nil)
	require.NoError(t, err)
	require.NotZero(t, req.ID)

	requests, err := store.ListRequestsBySecret(secret.ID)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	outstanding, err := store.ListOutstandingRequests()
	require.NoError(t, err)
	require.Len(t, outstanding, 1)

	approved, err := store.ApproveRequest(req.ID, true, "ok", "approver")
	require.NoError(t, err)
	require.NotNil(t, approved.Approved)
	require.True(t, *approved.Approved)
}

func TestMemoryStoreUserLifecycle(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	user, err := store.AddUser("admin", "hash", true, true, true, false, "local")
	require.NoError(t, err)
	require.NotZero(t, user.ID)

	loaded, err := store.GetUserByUsername("ADMIN")
	require.NoError(t, err)
	require.Equal(t, user.ID, loaded.ID)
	require.True(t, loaded.CanApprove)
}

func TestMemoryStoreListUsers(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	_, err := store.AddUser("first", "hash", true, false, true, false, "local")
	require.NoError(t, err)
	_, err = store.AddUser("second", "hash", false, true, true, false, "local")
	require.NoError(t, err)

	users, err := store.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 2)
	require.Equal(t, "first", users[0].Username)
	require.Equal(t, "second", users[1].Username)
}

func TestMemoryStoreUpdateAndDeleteUser(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	user, err := store.AddUser("first", "hash", true, false, true, false, "local")
	require.NoError(t, err)

	updated, err := store.UpdateUser(user.ID, "updated", false, true, false, true, "saml")
	require.NoError(t, err)
	require.Equal(t, "updated", updated.Username)
	require.False(t, updated.IsStaff)
	require.True(t, updated.CanApprove)
	require.False(t, updated.LocalLoginEnabled)
	require.True(t, updated.MustResetPassword)

	updated, err = store.UpdateUserPassword(user.ID, "newhash", false)
	require.NoError(t, err)
	require.Equal(t, "newhash", updated.PasswordHash)
	require.True(t, updated.LocalLoginEnabled)
	require.False(t, updated.MustResetPassword)

	err = store.DeleteUser(user.ID)
	require.NoError(t, err)
	_, err = store.GetUserByID(user.ID)
	require.Error(t, err)
}

func TestMemoryStoreCleanupRequests(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	computer, err := store.AddComputer("SERIAL9", "user", "Mac")
	require.NoError(t, err)
	secret, err := store.AddSecret(computer.ID, "recovery_key", "secret", false)
	require.NoError(t, err)
	approved := true
	request, err := store.AddRequest(secret.ID, "user", "reason", "approver", &approved)
	require.NoError(t, err)

	store.mu.Lock()
	old := time.Now().Add(-8 * 24 * time.Hour)
	request.DateApproved = &old
	store.mu.Unlock()

	count, err := store.CleanupRequests(time.Now().Add(-7 * 24 * time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.False(t, request.Current)
}

func TestMemoryStoreUpsertComputer(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	now := time.Now()
	computer, err := store.UpsertComputer("SERIAL", "user", "Mac", now)
	require.NoError(t, err)
	require.Equal(t, "SERIAL", computer.Serial)

	updated, err := store.UpsertComputer("SERIAL", "user2", "Mac2", now.Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, computer.ID, updated.ID)
	require.Equal(t, "user2", updated.Username)
	require.Equal(t, "Mac2", updated.ComputerName)
}

func TestMemoryStoreLatestSecretByType(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	computer, err := store.AddComputer("SERIAL7", "user", "Mac")
	require.NoError(t, err)

	first, err := store.AddSecret(computer.ID, "recovery_key", "secret1", false)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	second, err := store.AddSecret(computer.ID, "recovery_key", "secret2", true)
	require.NoError(t, err)

	latest, err := store.GetLatestSecretByComputerAndType(computer.ID, "recovery_key")
	require.NoError(t, err)
	require.Equal(t, second.ID, latest.ID)
	require.NotEqual(t, first.ID, latest.ID)
}
