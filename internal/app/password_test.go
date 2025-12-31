package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := hashPassword("secret")
	require.NoError(t, err)
	require.True(t, verifyPassword("secret", hash))
	require.False(t, verifyPassword("wrong", hash))
}

func TestPasswordHashRejectsEmpty(t *testing.T) {
	_, err := hashPassword("")
	require.Error(t, err)
}
