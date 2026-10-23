// SPDX-License-Identifier: BSD-3-Clause
package net

import "context"

// ConnectionsSnapshot holds the connections of every process, read in one pass over the system's connection tables
// and grouped by pid. Reading the connections of many processes from one snapshot parses each table once instead of
// once per process. Connections opened after the snapshot was taken are not seen. Safe for concurrent use.
type ConnectionsSnapshot struct {
	byPid map[int32][]ConnectionStat
}

// NewConnectionsSnapshot reads the connections of the given kind ("all", "tcp", "udp", "inet", ...) of every
// process once.
func NewConnectionsSnapshot(kind string) (*ConnectionsSnapshot, error) {
	return NewConnectionsSnapshotWithContext(context.Background(), kind)
}

// Pid returns the connections process pid had when the snapshot was taken, or nil when it had none.
func (s *ConnectionsSnapshot) Pid(pid int32) []ConnectionStat {
	return s.byPid[pid]
}

// connectionsSnapshotOf groups stats by their Pid.
func connectionsSnapshotOf(stats []ConnectionStat) *ConnectionsSnapshot {
	byPid := make(map[int32][]ConnectionStat)
	for _, stat := range stats {
		byPid[stat.Pid] = append(byPid[stat.Pid], stat)
	}
	return &ConnectionsSnapshot{byPid: byPid}
}
