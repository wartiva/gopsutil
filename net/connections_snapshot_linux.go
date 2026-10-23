// SPDX-License-Identifier: BSD-3-Clause
//go:build linux

package net

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/wartiva/gopsutil/v4/internal/common"
)

// isUnixSocketFd reports whether /proc/<pid>/fd/<fd> under root is the unix domain socket with the given inode. sockfs
// answers the system.sockprotoname attribute with the socket's protocol name, which its owner cannot change. Tests
// replace it, since a fake /proc tree has no sockets.
//
// The fd's file is pinned with O_PATH, which calls no filesystem open, and the pinned file is checked to be that very
// socket before the attribute is read through it. After the fd table was scanned, the owner can swap the fd for a FUSE
// file, or the pid can be reused; a getxattr by path would then be served, and could be blocked forever, by the FUSE
// daemon.
var isUnixSocketFd = func(root string, pid int32, fd uint32, inode string) bool {
	link := filepath.Join(root, strconv.Itoa(int(pid)), "fd", strconv.FormatUint(uint64(fd), 10))
	pinned, err := unix.Open(link, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(pinned)
	self := "/proc/self/fd/" + strconv.Itoa(pinned)
	// readlink of a magic link only formats the path, so it makes no filesystem call
	if target, err := os.Readlink(self); err != nil || target != "socket:["+inode+"]" {
		return false
	}
	var buf [32]byte
	n, err := unix.Getxattr(self, "system.sockprotoname", buf[:])
	return err == nil && strings.HasPrefix(string(buf[:n]), "UNIX")
}

// socketRow is one row of a /proc/<pid>/net connection table, with its position for ordering.
type socketRow struct {
	conn connTmp
	// namespace is the inode of the network namespace whose tables list the row.
	namespace uint64
	// kindIndex and rowIndex are the table's position in the kind's table list and the row's line in that table, so
	// a process's connections come out in the order the per-process read produces them.
	kindIndex int
	rowIndex  int
}

// netnsProcs is a network namespace and the processes in it that hold sockets.
type netnsProcs struct {
	key  nsKey
	pids []int32
}

// NewConnectionsSnapshotWithContext reads the connections of the given kind of every process once and groups them by
// pid.
//
// Each process's socket inodes come from /proc/<pid>/fd and its network namespace from /proc/<pid>/ns/net. The tables
// of each namespace are parsed once, read through /proc/<pid>/net of a process in it, which shows that process's own
// namespace without switching the calling thread into it. A process's connections are then the rows whose inode it
// holds, deduplicated and ordered as [ConnectionsPidWithContext] returns them. Unlike that function, each connection
// is listed once however many namespaces exist.
//
// A socket a process holds but its own namespace does not list, because it was created before an unshare or received
// from another namespace, is taken from the one other namespace whose tcp or udp tables list it; Namespace is then
// the inode of the namespace that lists the socket, not of the process's own. Unix rows are never taken across
// namespaces, and a unix row is attributed to a process only when the process's fd is a unix socket, since a local
// user can inject unix rows through an unescaped newline in a socket path. Connection Uids are not read. Processes
// that exit or deny access during the read are skipped.
func NewConnectionsSnapshotWithContext(ctx context.Context, kind string) (*ConnectionsSnapshot, error) {
	tmap, ok := netConnectionKindMap[kind]
	if !ok {
		return nil, fmt.Errorf("invalid kind, %s", kind)
	}
	root := common.HostProcWithContext(ctx)
	pids, err := PidsWithContext(ctx)
	if err != nil {
		return nil, err
	}

	pidInodes := make(map[int32]map[string][]inodeMap)
	// holders counts the processes holding each inode, so a namespace keeps only the rows held outside it
	holders := make(map[string]int)
	var namespaces []*netnsProcs
	byKey := make(map[nsKey]*netnsProcs)
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		inodes, err := getProcInodes(root, pid, 0)
		if err != nil || len(inodes) == 0 {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(filepath.Join(root, strconv.Itoa(int(pid)), "ns", "net"), &st); err != nil {
			continue
		}
		key := nsKey{Dev: st.Dev, Ino: st.Ino}
		ns, seen := byKey[key]
		if !seen {
			ns = &netnsProcs{key: key}
			byKey[key] = ns
			namespaces = append(namespaces, ns)
		}
		ns.pids = append(ns.pids, pid)
		pidInodes[pid] = inodes
		for inode := range inodes {
			holders[inode]++
		}
	}

	// match each namespace's processes as soon as its tables are parsed, so only one namespace's rows, and the inet
	// rows of sockets held outside their namespace, are held at once
	pidRows := make(map[int32][]socketRow, len(pidInodes))
	foreign := make(map[string][]socketRow)
	for _, ns := range namespaces {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rows, err := readNetnsTables(root, ns.key, ns.pids, tmap)
		if err != nil {
			return nil, err
		}
		matches := make(map[string]int)
		for _, pid := range ns.pids {
			for inode, fds := range pidInodes[pid] {
				r := rows[inode]
				if len(r) == 0 {
					continue
				}
				if r[0].conn.family == syscall.AF_UNIX && !isUnixSocketFd(root, pid, fds[0].fd, inode) {
					// an injected unix row names a socket that is not a unix socket; leave the inode unmatched so the
					// namespace that really lists it can still supply its row
					continue
				}
				matches[inode]++
				delete(pidInodes[pid], inode)
				row := r[0]
				row.conn.fd = fds[0].fd
				pidRows[pid] = append(pidRows[pid], row)
			}
		}
		for inode, r := range rows {
			if r[0].conn.family != syscall.AF_UNIX && holders[inode] > matches[inode] {
				foreign[inode] = append(foreign[inode], r[0])
			}
		}
	}

	// attach each socket left unmatched in its holder's namespace when exactly one other namespace lists it
	for pid, inodes := range pidInodes {
		for inode, fds := range inodes {
			if r := foreign[inode]; len(r) == 1 {
				row := r[0]
				row.conn.fd = fds[0].fd
				pidRows[pid] = append(pidRows[pid], row)
			}
		}
	}

	byPid := make(map[int32][]ConnectionStat, len(pidRows))
	for pid, rows := range pidRows {
		if conns := pidConnections(pid, rows); len(conns) > 0 {
			byPid[pid] = conns
		}
	}
	return &ConnectionsSnapshot{byPid: byPid}, nil
}

// readNetnsTables parses the tables in tmap of the network namespace key that pids share, keyed by socket inode. It
// reads them through /proc/<pid>/net of the first of pids still in that namespace, so a process that exits after the
// scan does not lose the namespace, and a pid reused by a process in another namespace is not read in its place.
func readNetnsTables(root string, key nsKey, pids []int32, tmap []netConnectionKindType) (map[string][]socketRow, error) {
	for _, pid := range pids {
		rows := make(map[string][]socketRow)
		procDir := filepath.Join(root, strconv.Itoa(int(pid)))
		var err error
		for kindIndex, kind := range tmap {
			if err = readSocketTable(filepath.Join(procDir, "net", kind.filename), kind, kindIndex, key.Ino,
				rows); err != nil {
				break
			}
		}
		if err != nil {
			if !os.IsNotExist(err) && !os.IsPermission(err) {
				return nil, err
			}
			continue
		}
		// the tables are the namespace's only if pid was still in it after they were read
		var st syscall.Stat_t
		if syscall.Stat(filepath.Join(procDir, "ns", "net"), &st) != nil || (nsKey{Dev: st.Dev, Ino: st.Ino}) != key {
			continue
		}
		dropForgedRows(rows)
		return rows, nil
	}
	// every process in the namespace exited, left it or denied access: no connections are reported for it
	return map[string][]socketRow{}, nil
}

// dropForgedRows leaves at most one row per inode. The kernel assigns socket inodes system-wide, so a real socket
// occupies exactly one row of its namespace's tables; a repeated inode means a row was injected through an unescaped
// newline in a unix socket path, which any local user can bind. Tcp and udp rows carry no caller-controlled text, so
// when exactly one of an inode's rows is not a unix row, that row is kept and the unix rows are dropped. When all of
// them are unix rows, one is kept without its path and socket type, which may be forged, so the socket stays listed
// with family AF_UNIX only. Otherwise none of the inode's rows can be trusted and all are dropped.
func dropForgedRows(rows map[string][]socketRow) {
	for inode, r := range rows {
		if len(r) == 1 {
			continue
		}
		var inet []socketRow
		for _, row := range r {
			if row.conn.family != syscall.AF_UNIX {
				inet = append(inet, row)
			}
		}
		switch len(inet) {
		case 1:
			rows[inode] = inet
		case 0:
			// every row is a unix row and any of them may be forged: keep the socket, which the match loop only
			// attributes after isUnixSocketFd confirms it, but none of its caller-controlled text, so a forged row
			// can neither hide a real unix socket nor relabel it. A single forged row can still relabel a unix socket
			// its holder received from another namespace, where no real row repeats the inode; closing that needs
			// NETLINK_SOCK_DIAG/UNIX_DIAG.
			row := r[0]
			row.conn = connTmp{family: syscall.AF_UNIX, status: "NONE"}
			rows[inode] = []socketRow{row}
		default:
			delete(rows, inode)
		}
	}
}

// readSocketTable adds the rows of one /proc/<pid>/net table of the network namespace with inode namespace to rows,
// keyed by socket inode. A missing IPv6 table means IPv6 is not supported and adds nothing.
func readSocketTable(
	file string,
	kind netConnectionKindType,
	kindIndex int,
	namespace uint64,
	rows map[string][]socketRow,
) error {
	// Read the contents of the /proc file with a single read sys call, as processInet and processUnix do.
	contents, err := os.ReadFile(file)
	if err != nil {
		if strings.HasSuffix(file, "6") && os.IsNotExist(err) {
			return nil
		}
		return err
	}
	lines := bytes.Split(contents, []byte("\n"))
	for rowIndex, line := range lines[min(1, len(lines)):] {
		var conn connTmp
		var inode string
		var ok bool
		if kind.family == syscall.AF_UNIX {
			conn, inode, ok = parseUnixRow(string(line), kind)
		} else {
			conn, inode, ok = parseInetRow(string(line), kind)
		}
		if ok {
			rows[inode] = append(rows[inode], socketRow{
				conn:      conn,
				namespace: namespace,
				kindIndex: kindIndex,
				rowIndex:  rowIndex,
			})
		}
	}
	return nil
}

// parseInetRow parses one row of a tcp, tcp6, udp or udp6 table as processInet does, returning its socket inode.
func parseInetRow(line string, kind netConnectionKindType) (connTmp, string, bool) {
	l := strings.Fields(line)
	if len(l) < 10 {
		return connTmp{}, "", false
	}
	status := l[3]
	if kind.sockType == syscall.SOCK_STREAM {
		status = tcpStatuses[status]
	} else {
		status = "NONE"
	}
	la, err := decodeAddress(kind.family, l[1])
	if err != nil {
		return connTmp{}, "", false
	}
	ra, err := decodeAddress(kind.family, l[2])
	if err != nil {
		return connTmp{}, "", false
	}
	return connTmp{family: kind.family, sockType: kind.sockType, laddr: la, raddr: ra, status: status}, l[9], true
}

// parseUnixRow parses one row of the unix table as processUnix does, returning its socket inode. Rows with fewer
// than the seven fields that carry the inode are skipped.
func parseUnixRow(line string, kind netConnectionKindType) (connTmp, string, bool) {
	tokens := strings.Fields(line)
	if len(tokens) < 7 {
		return connTmp{}, "", false
	}
	st, err := strconv.ParseInt(tokens[4], 10, 32)
	if err != nil {
		return connTmp{}, "", false
	}
	var path string
	if len(tokens) == 8 {
		path = tokens[len(tokens)-1]
	}
	return connTmp{
		family:   kind.family,
		sockType: uint32(st),
		laddr:    Addr{IP: path},
		status:   "NONE",
		path:     path,
	}, tokens[6], true
}

// pidConnections orders the rows process pid holds as the per-process read produces them and drops rows that repeat
// a connection already listed, as statsFromInodesWithContext does.
func pidConnections(pid int32, rows []socketRow) []ConnectionStat {
	slices.SortFunc(rows, func(a, b socketRow) int {
		return cmp.Or(cmp.Compare(a.kindIndex, b.kindIndex), cmp.Compare(a.rowIndex, b.rowIndex))
	})
	seen := make(map[string]struct{}, len(rows))
	var conns []ConnectionStat
	for _, row := range rows {
		c := row.conn
		key := fmt.Sprintf("%d-%s:%d-%s:%d-%s", c.sockType, c.laddr.IP, c.laddr.Port, c.raddr.IP, c.raddr.Port, c.status)
		if c.family == syscall.AF_UNIX && c.sockType == 0 {
			// a unix row stripped by dropForgedRows has no distinguishing fields, so keep each such socket by its fd
			key += "-fd" + strconv.FormatUint(uint64(c.fd), 10)
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		conns = append(conns, ConnectionStat{
			Fd:        c.fd,
			Family:    c.family,
			Type:      c.sockType,
			Laddr:     c.laddr,
			Raddr:     c.raddr,
			Status:    c.status,
			Pid:       pid,
			Namespace: row.namespace,
		})
	}
	return conns
}
