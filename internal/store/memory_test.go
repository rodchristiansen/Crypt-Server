package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryStoreComputerLifecycle(t *testing.T) {
	store := NewMemoryStore()
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
	store := NewMemoryStore()
	computer, err := store.AddComputer("SERIAL2", "user2", "iMac")
	require.NoError(t, err)

	secret, err := store.AddSecret(computer.ID, "recovery_key", "secret-value", false)
	require.NoError(t, err)

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
