// SPDX-License-Identifier: BSD-3-Clause
//go:build linux

package net

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gcommon "github.com/wartiva/gopsutil/v4/common"
)

const (
	tcpHeader  = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	unixHeader = "Num       RefCount Protocol Flags    Type St Inode Path\n"
)

// fakeProc is a process in a fake /proc tree: the socket inode each fd links to, the namespace file its ns/net links
// to, and the net tables it serves, if any.
type fakeProc struct {
	pid    int
	fds    map[string]string
	netns  string
	tables map[string]string
}

// writeFakeProc builds root/<pid>/{fd,ns/net,net/*} for p.
func writeFakeProc(t *testing.T, root string, p fakeProc) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(p.pid))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "fd"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ns"), 0o755))
	for fd, target := range p.fds {
		require.NoError(t, os.Symlink(target, filepath.Join(dir, "fd", fd)))
	}
	// a hard link makes processes of one namespace share the inode of the ns/net file, as the kernel does
	require.NoError(t, os.Link(p.netns, filepath.Join(dir, "ns", "net")))
	if p.tables != nil {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "net"), 0o755))
		for name, contents := range p.tables {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "net", name), []byte(contents), 0o644))
		}
	}
}

// inetRow returns one tcp or udp table row for a socket bound to local (hex address:port) in state st with inode.
func inetRow(local, st, inode string) string {
	return "   0: " + local + " 00000000:0000 " + st + " 00000000:00000000 00:00000000 00000000  1000        0 " +
		inode + " 1 0\n"
}

// inodeOf returns the inode number of file.
func inodeOf(t *testing.T, file string) uint64 {
	t.Helper()
	var st syscall.Stat_t
	require.NoError(t, syscall.Stat(file, &st))
	return st.Ino
}

// TestConnectionsSnapshotFakeProc checks the snapshot against a fake /proc tree: each namespace's tables are matched
// only against the sockets of processes in that namespace, a process with several fds on one socket lists it once,
// a namespace whose first process serves no tables is read through another, a missing IPv6 table is tolerated, a
// unix row injected through a socket path neither hides the tcp socket whose inode it repeats nor is attributed to a
// process whose fd is not a unix socket, a socket held outside the namespace that lists it is attributed to its
// holder, and the kind filters the tables read.
func TestConnectionsSnapshotFakeProc(t *testing.T) {
	root := t.TempDir()
	ns1 := filepath.Join(root, "ns1")
	ns2 := filepath.Join(root, "ns2")
	ns3 := filepath.Join(root, "ns3")
	ns4 := filepath.Join(root, "ns4")
	for _, ns := range []string{ns1, ns2, ns3, ns4} {
		require.NoError(t, os.WriteFile(ns, nil, 0o644))
	}
	require.NoError(t, os.MkdirAll(filepath.Join(root, "self"), 0o755)) // non-numeric entries are not processes

	// only pid 10's fd 4 is a unix socket; pid 40's fd 3 is, say, a netlink socket that no table lists
	unixFds := map[string]bool{"10/4": true, "70/3": true, "70/4": true}
	origIsUnixSocketFd := isUnixSocketFd
	isUnixSocketFd = func(_ string, pid int32, fd uint32, _ string) bool {
		return unixFds[strconv.Itoa(int(pid))+"/"+strconv.FormatUint(uint64(fd), 10)]
	}
	t.Cleanup(func() { isUnixSocketFd = origIsUnixSocketFd })

	ns1Tables := map[string]string{
		// inode 100: 127.0.0.1:8080 listening; inode 102: 127.0.0.1:8081 listening, held only by pid 50 in ns3; inode
		// 103: 127.0.0.1:8082 listening, held only by pid 60 in ns4
		"tcp": tcpHeader + inetRow("0100007F:1F90", "0A", "100") + inetRow("0100007F:1F91", "0A", "102") +
			inetRow("0100007F:1F92", "0A", "103"),
		"tcp6": tcpHeader,
		// udp6 is absent: IPv6 not supported in this namespace
		// inode 101: 0.0.0.0:53
		"udp": tcpHeader + inetRow("00000000:0035", "07", "101"),
		// row 200 is real; the socket bound as "x\n... 100 /forged\n... 500 /forged" injects a row repeating inode
		// 100, pid 10's TCP listener, and a row claiming inode 500, pid 40's non-unix socket
		"unix": unixHeader + "0000000000000000: 00000002 00000000 00010000 0001 01 200 /run/a.sock\n" +
			"0000000000000000: 00000002 00000000 00010000 0001 01 300 x\n" +
			// rows 600 and 601 are pid 70's real unix sockets; other socket paths inject rows repeating their inodes
			"0000000000000000: 00000002 00000000 00010000 0001 01 600 /run/b.sock\n" +
			"0000000000000000: 00000002 00000000 00010000 0002 01 600 /evil\n" +
			"0000000000000000: 00000002 00000000 00010000 0001 01 601 /run/c.sock\n" +
			"0000000000000000: 00000002 00000000 00010000 0001 01 601 /evil\n" +
			"0000000000000000: 00000002 00000000 00010000 0001 01 100 /forged\n" +
			"0000000000000000: 00000002 00000000 00010000 0001 01 500 /forged\n",
	}
	ns2Tables := map[string]string{
		// inode 400: 127.0.0.1:9090
		"tcp":  tcpHeader + inetRow("0100007F:2382", "0A", "400"),
		"tcp6": tcpHeader,
		"udp":  tcpHeader,
		"udp6": tcpHeader,
		"unix": unixHeader,
	}
	writeFakeProc(t, root, fakeProc{
		pid:   10,
		fds:   map[string]string{"3": "socket:[100]", "4": "socket:[200]", "5": "socket:[100]", "6": "/dev/null"},
		netns: ns1, tables: ns1Tables,
	})
	// pid 11 shares pid 10's namespace but serves no tables, so ns1 is read through pid 10 whichever comes first
	writeFakeProc(t, root, fakeProc{pid: 11, fds: map[string]string{"3": "socket:[101]"}, netns: ns1})
	writeFakeProc(t, root, fakeProc{pid: 20, fds: map[string]string{"3": "socket:[400]"}, netns: ns2, tables: ns2Tables})
	writeFakeProc(t, root, fakeProc{pid: 30, fds: map[string]string{}, netns: ns1})
	writeFakeProc(t, root, fakeProc{pid: 40, fds: map[string]string{"3": "socket:[500]"}, netns: ns1})
	// pid 50 unshared into ns3, which serves no tables, after creating the ns1 socket 102
	writeFakeProc(t, root, fakeProc{pid: 50, fds: map[string]string{"3": "socket:[102]"}, netns: ns3})
	writeFakeProc(t, root, fakeProc{pid: 70, fds: map[string]string{"3": "socket:[600]", "4": "socket:[601]"}, netns: ns1})
	// pid 60 unshared into ns4 after creating the ns1 socket 103, then injected a unix row claiming 103 into ns4's table
	writeFakeProc(t, root, fakeProc{
		pid: 60, fds: map[string]string{"3": "socket:[103]"}, netns: ns4,
		tables: map[string]string{
			"tcp": tcpHeader, "tcp6": tcpHeader, "udp": tcpHeader, "udp6": tcpHeader,
			"unix": unixHeader + "0000000000000000: 00000002 00000000 00010000 0001 01 103 /forged\n",
		},
	})

	ctx := context.WithValue(context.Background(), gcommon.EnvKey, gcommon.EnvMap{gcommon.HostProcEnvKey: root})
	ns1Ino, ns2Ino := inodeOf(t, ns1), inodeOf(t, ns2)

	snapshot, err := NewConnectionsSnapshotWithContext(ctx, "all")
	require.NoError(t, err)

	// inode 100 is repeated by the injected unix row, which is dropped while the tcp row is kept
	pid10 := snapshot.Pid(10)
	require.Len(t, pid10, 2, "%+v", pid10)
	assert.Equal(t, "LISTEN", pid10[0].Status)
	assert.Equal(t, Addr{IP: "127.0.0.1", Port: 8080}, pid10[0].Laddr)
	assert.Contains(t, []uint32{3, 5}, pid10[0].Fd)
	assert.Equal(t, uint32(syscall.AF_UNIX), pid10[1].Family)
	assert.Equal(t, "/run/a.sock", pid10[1].Laddr.IP)
	assert.Equal(t, uint32(4), pid10[1].Fd)
	for _, c := range pid10 {
		assert.Equal(t, int32(10), c.Pid)
		assert.Equal(t, ns1Ino, c.Namespace)
		assert.NotEqual(t, "/forged", c.Laddr.IP)
	}

	assert.Nil(t, snapshot.Pid(40), "injected unix row attributed to a non-unix socket")

	pid50 := snapshot.Pid(50)
	require.Len(t, pid50, 1, "%+v", pid50)
	assert.Equal(t, Addr{IP: "127.0.0.1", Port: 8081}, pid50[0].Laddr)
	assert.Equal(t, ns1Ino, pid50[0].Namespace, "labelled with the namespace that lists the socket")

	// forged rows repeating pid 70's unix sockets neither hide them, label them nor merge them: each is kept with only
	// its family
	pid70 := snapshot.Pid(70)
	require.Len(t, pid70, 2, "%+v", pid70)
	for _, c := range pid70 {
		assert.Equal(t, uint32(syscall.AF_UNIX), c.Family)
		assert.Equal(t, uint32(0), c.Type)
		assert.Empty(t, c.Laddr.IP)
	}
	assert.ElementsMatch(t, []uint32{3, 4}, []uint32{pid70[0].Fd, pid70[1].Fd})

	// the forged unix row in pid 60's own namespace does not hide the ns1 tcp socket it holds
	pid60 := snapshot.Pid(60)
	require.Len(t, pid60, 1, "%+v", pid60)
	assert.Equal(t, Addr{IP: "127.0.0.1", Port: 8082}, pid60[0].Laddr)
	assert.Equal(t, ns1Ino, pid60[0].Namespace)

	pid11 := snapshot.Pid(11)
	require.Len(t, pid11, 1)
	assert.Equal(t, Addr{IP: "0.0.0.0", Port: 53}, pid11[0].Laddr)
	assert.Equal(t, "NONE", pid11[0].Status)
	assert.Equal(t, ns1Ino, pid11[0].Namespace)

	pid20 := snapshot.Pid(20)
	require.Len(t, pid20, 1)
	assert.Equal(t, Addr{IP: "127.0.0.1", Port: 9090}, pid20[0].Laddr)
	assert.Equal(t, ns2Ino, pid20[0].Namespace)

	// a pid that now resolves to another namespace than the one it was grouped under is not read in its place
	var ns2St syscall.Stat_t
	require.NoError(t, syscall.Stat(ns2, &ns2St))
	stale, err := readNetnsTables(root, nsKey{Dev: ns2St.Dev, Ino: ns2St.Ino}, []int32{10}, netConnectionKindMap["tcp"])
	require.NoError(t, err)
	assert.Empty(t, stale)

	assert.Nil(t, snapshot.Pid(30), "process without sockets")
	assert.Nil(t, snapshot.Pid(99), "unknown pid")

	// kind tcp reads no unix table, so only the listener is listed, once, with one of its two fds
	tcpOnly, err := NewConnectionsSnapshotWithContext(ctx, "tcp")
	require.NoError(t, err)
	tcp10 := tcpOnly.Pid(10)
	require.Len(t, tcp10, 1)
	assert.Equal(t, "LISTEN", tcp10[0].Status)
	assert.Equal(t, Addr{IP: "127.0.0.1", Port: 8080}, tcp10[0].Laddr)
	assert.Equal(t, uint32(syscall.AF_INET), tcp10[0].Family)
	assert.Equal(t, uint32(syscall.SOCK_STREAM), tcp10[0].Type)
	assert.Contains(t, []uint32{3, 5}, tcp10[0].Fd)
	assert.Equal(t, ns1Ino, tcp10[0].Namespace)
	assert.Nil(t, tcpOnly.Pid(11), "udp socket listed for kind tcp")

	_, err = NewConnectionsSnapshotWithContext(ctx, "bogus")
	require.Error(t, err)
}

// TestIsUnixSocketFd checks, on the live system, that only an fd that is the unix socket with the named inode passes.
func TestIsUnixSocketFd(t *testing.T) {
	unixListener, err := net.Listen("unix", "@gopsutil-is-unix-socket-fd-"+strconv.Itoa(os.Getpid()))
	require.NoError(t, err)
	t.Cleanup(func() { unixListener.Close() })
	unixFile, err := unixListener.(*net.UnixListener).File()
	require.NoError(t, err)
	t.Cleanup(func() { unixFile.Close() })

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcpListener.Close() })
	tcpFile, err := tcpListener.(*net.TCPListener).File()
	require.NoError(t, err)
	t.Cleanup(func() { tcpFile.Close() })

	regular, err := os.Open(os.Args[0])
	require.NoError(t, err)
	t.Cleanup(func() { regular.Close() })

	// inodeOfFd returns the socket inode /proc/self/fd/<fd> links to.
	inodeOfFd := func(f *os.File) string {
		target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
		require.NoError(t, err)
		return strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	}
	pid := int32(os.Getpid())
	unixInode, tcpInode := inodeOfFd(unixFile), inodeOfFd(tcpFile)

	tests := []struct {
		name  string
		fd    uintptr
		inode string
		want  bool
	}{
		{name: "unix socket", fd: unixFile.Fd(), inode: unixInode, want: true},
		{name: "unix socket under another inode", fd: unixFile.Fd(), inode: tcpInode, want: false},
		{name: "tcp socket", fd: tcpFile.Fd(), inode: tcpInode, want: false},
		{name: "regular file", fd: regular.Fd(), inode: unixInode, want: false},
		{name: "closed fd", fd: 1 << 20, inode: unixInode, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isUnixSocketFd("/proc", pid, uint32(tt.fd), tt.inode))
		})
	}
}

// TestConnectionsSnapshotMatchesPerPid checks, on the live system, that the snapshot lists this process's TCP and
// UDP sockets as the per-process read does. The snapshot does not read uids, so the reference skips them too. The
// per-process read repeats each connection once per network namespace on the host, so the reference keeps only the
// copies labelled with this process's own namespace.
func TestConnectionsSnapshotMatchesPerPid(t *testing.T) {
	var st syscall.Stat_t
	require.NoError(t, syscall.Stat("/proc/self/ns/net", &st))
	ownNamespace := st.Ino
	assertSnapshotMatchesPerPid(t, func(ctx context.Context, kind string, pid int32) ([]ConnectionStat, error) {
		all, err := ConnectionsPidWithoutUidsWithContext(ctx, kind, pid)
		if err != nil {
			return nil, err
		}
		var own []ConnectionStat
		for _, c := range all {
			if c.Namespace == ownNamespace {
				own = append(own, c)
			}
		}
		return own, nil
	})
}
