// SPDX-License-Identifier: BSD-3-Clause
//go:build linux || windows

package net

import (
	"context"
	gonet "net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertSnapshotMatchesPerPid opens a TCP listener and a UDP socket and checks that the snapshot lists both under this
// process's pid, with the same connections perPidRead returns for it.
func assertSnapshotMatchesPerPid(
	t *testing.T,
	perPidRead func(ctx context.Context, kind string, pid int32) ([]ConnectionStat, error),
) {
	t.Helper()
	listener, err := gonet.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	udp, err := gonet.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	tcpPort := uint32(listener.Addr().(*gonet.TCPAddr).Port)
	udpPort := uint32(udp.LocalAddr().(*gonet.UDPAddr).Port)

	pid := int32(os.Getpid())
	snapshot, err := NewConnectionsSnapshotWithContext(context.Background(), "inet")
	require.NoError(t, err)
	perPid, err := perPidRead(context.Background(), "inet", pid)
	require.NoError(t, err)

	got := snapshot.Pid(pid)
	var sawTCP, sawUDP bool
	for _, c := range got {
		assert.Equal(t, pid, c.Pid)
		sawTCP = sawTCP || (c.Laddr.Port == tcpPort && c.Status == "LISTEN")
		sawUDP = sawUDP || c.Laddr.Port == udpPort
	}
	assert.True(t, sawTCP, "TCP listener on %d missing: %+v", tcpPort, got)
	assert.True(t, sawUDP, "UDP socket on %d missing: %+v", udpPort, got)
	assert.ElementsMatch(t, perPid, got, "snapshot differs from the per-process read")
}
