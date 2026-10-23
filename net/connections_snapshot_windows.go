// SPDX-License-Identifier: BSD-3-Clause
//go:build windows

package net

import (
	"context"
	"fmt"
)

// NewConnectionsSnapshotWithContext reads each TCP and UDP table the kind needs once, through GetExtendedTcpTable and
// GetExtendedUdpTable, and groups the rows by their owning pid. A table that cannot be read is skipped, as
// [ConnectionsPidWithContext] skips it.
func NewConnectionsSnapshotWithContext(_ context.Context, kind string) (*ConnectionsSnapshot, error) {
	tmap, ok := netConnectionKindMap[kind]
	if !ok {
		return nil, fmt.Errorf("invalid kind, %s", kind)
	}
	stats, err := getProcInet(tmap, 0)
	if err != nil {
		return nil, err
	}
	return connectionsSnapshotOf(stats), nil
}
