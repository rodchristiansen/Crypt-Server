package store

import (
	"testing"

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
	user, err := store.AddUser("admin", "hash", true, true, true)
	require.NoError(t, err)
	require.NotZero(t, user.ID)

	loaded, err := store.GetUserByUsername("ADMIN")
	require.NoError(t, err)
	require.Equal(t, user.ID, loaded.ID)
	require.True(t, loaded.CanApprove)
}

func TestMemoryStoreListUsers(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	_, err := store.AddUser("first", "hash", true, false, true)
	require.NoError(t, err)
	_, err = store.AddUser("second", "hash", false, true, true)
	require.NoError(t, err)

	users, err := store.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 2)
	require.Equal(t, "first", users[0].Username)
	require.Equal(t, "second", users[1].Username)
}

func TestMemoryStoreUpdateAndDeleteUser(t *testing.T) {
	store := NewMemoryStore(testCodec(t))
	user, err := store.AddUser("first", "hash", true, false, true)
	require.NoError(t, err)

	updated, err := store.UpdateUser(user.ID, "updated", false, true, false)
	require.NoError(t, err)
	require.Equal(t, "updated", updated.Username)
	require.False(t, updated.IsStaff)
	require.True(t, updated.CanApprove)
	require.False(t, updated.HasUsablePassword)

	updated, err = store.UpdateUserPassword(user.ID, "newhash", true)
	require.NoError(t, err)
	require.Equal(t, "newhash", updated.PasswordHash)
	require.True(t, updated.HasUsablePassword)

	err = store.DeleteUser(user.ID)
	require.NoError(t, err)
	_, err = store.GetUserByID(user.ID)
	require.Error(t, err)
}
