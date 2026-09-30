package storage

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestNewStorageDoesNotLogPassword(t *testing.T) {
	hook := test.NewGlobal()
	defer hook.Reset()
	level := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	defer logrus.SetLevel(level)

	_, err := NewStorage("postgresql://wgas:s3cr3t-password@localhost:5432/wgas")
	require.NoError(t, err)

	require.NotEmpty(t, hook.AllEntries())
	for _, entry := range hook.AllEntries() {
		require.NotContains(t, entry.Message, "s3cr3t-password")
	}
}

func TestNewStorageErrorsDoNotContainPassword(t *testing.T) {
	for _, uri := range []string{
		"unknown://wgas:s3cr3t-password@localhost/wgas",
		"postgresql://wgas:s3cr3t-password@localhost:invalid/wgas",
	} {
		_, err := NewStorage(uri)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "s3cr3t-password")
	}
}
