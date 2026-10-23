// SPDX-License-Identifier: BSD-3-Clause
//go:build windows

package net

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConnectionsSnapshotMatchesPerPid checks that the snapshot lists this process's TCP and UDP sockets as
// ConnectionsPidWithContext does. Windows connections carry no uids, so the full per-process read is the reference.
func TestConnectionsSnapshotMatchesPerPid(t *testing.T) {
	assertSnapshotMatchesPerPid(t, ConnectionsPidWithContext)
}

// TestConnectionsSnapshotInvalidKind checks that an unknown kind is an error.
func TestConnectionsSnapshotInvalidKind(t *testing.T) {
	_, err := NewConnectionsSnapshotWithContext(context.Background(), "bogus")
	require.Error(t, err)
}
