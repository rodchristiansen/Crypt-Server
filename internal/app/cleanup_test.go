package app

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCleanupOldRequestsMarksNonCurrent(t *testing.T) {
	server, memStore, _ := newTestServer(t)
	computer, err := memStore.AddComputer("SERIAL10", "user", "Mac")
	require.NoError(t, err)
	secret, err := memStore.AddSecret(computer.ID, "recovery_key", "secret", false)
	require.NoError(t, err)
	approved := true
	request, err := memStore.AddRequest(secret.ID, "user", "reason", "approver", &approved)
	require.NoError(t, err)

	memStore.mu.Lock()
	old := time.Now().Add(-8 * 24 * time.Hour)
	request.DateApproved = &old
	memStore.mu.Unlock()

	server.cleanupOldRequests()
	require.False(t, request.Current)
}
