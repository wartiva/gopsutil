// SPDX-License-Identifier: BSD-3-Clause
//go:build !linux && !windows

package net

import "context"

// NewConnectionsSnapshotWithContext reads the connections of the given kind of every process once and groups them by
// pid.
func NewConnectionsSnapshotWithContext(ctx context.Context, kind string) (*ConnectionsSnapshot, error) {
	stats, err := ConnectionsWithContext(ctx, kind)
	if err != nil {
		return nil, err
	}
	return connectionsSnapshotOf(stats), nil
}
