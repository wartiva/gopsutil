// SPDX-License-Identifier: BSD-3-Clause
//go:build windows

package process

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wartiva/gopsutil/v4/internal/common"
	"golang.org/x/sys/windows"
)

// The tests in this file read and change the package-global file query state (fileQueriesInFlight,
// fileQueryObjects, fileQueryOwners, queryFile, queryHandleTable, handleTableSizeHint), so none of them may call
// t.Parallel.

// waitFileQueriesIdle waits until no file query from an earlier test is still in flight, so a test that inspects the
// global query state starts from an idle baseline.
func waitFileQueriesIdle(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		if fileQueriesInFlight.Load() != 0 {
			return false
		}
		empty := true
		fileQueryObjects.Range(func(_, _ any) bool {
			empty = false
			return false
		})
		fileQueryOwnersMu.Lock()
		owners := len(fileQueryOwners)
		fileQueryOwnersMu.Unlock()
		return empty && owners == 0
	}, 5*time.Second, 10*time.Millisecond, "file queries from an earlier test are still in flight")
}

// duplicateOwnHandle returns a new handle to the same file object as h in this process, which the caller hands to
// [regularFilePathOf] to close.
func duplicateOwnHandle(t *testing.T, h uintptr) windows.Handle {
	t.Helper()
	var dup windows.Handle
	require.NoError(t, windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(h),
		windows.CurrentProcess(), &dup, 0, false, windows.DUPLICATE_SAME_ACCESS))
	return dup
}

// blockFileQueries replaces queryFile with a query that blocks until the returned function is called, and restores
// the real query when the test ends.
func blockFileQueries(t *testing.T) (release func()) {
	t.Helper()
	unblock := make(chan struct{})
	savedQuery := queryFile
	queryFile = func(windows.Handle) (string, bool) {
		<-unblock
		return "", false
	}
	var released bool
	release = func() {
		if !released {
			released = true
			close(unblock)
		}
	}
	t.Cleanup(func() {
		release()
		queryFile = savedQuery
		waitFileQueriesIdle(t)
	})
	return release
}

// handleClosed reports whether h no longer refers to an open handle.
func handleClosed(h windows.Handle) bool {
	_, err := windows.GetFileType(h)
	return errors.Is(err, windows.ERROR_INVALID_HANDLE)
}

// TestOpenFilesSnapshot checks that a snapshot lists this process's open regular file once, with its handle value,
// and leaves out a directory and a named pipe it also holds open.
func TestOpenFilesSnapshot(t *testing.T) {
	waitFileQueriesIdle(t)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "open-file.txt")
	file, err := os.Create(filePath)
	require.NoError(t, err)
	defer file.Close()
	again, err := os.Open(filePath) // a second handle to the same path is reported once
	require.NoError(t, err)
	defer again.Close()

	dirHandle, err := os.Open(dir)
	require.NoError(t, err)
	defer dirHandle.Close()

	pipe, err := windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(`\\.\pipe\gopsutil-open-files-test`),
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE,
		1, 512, 512, 0, nil,
	)
	require.NoError(t, err)
	defer windows.CloseHandle(pipe)

	snapshot, err := NewOpenFilesSnapshot()
	require.NoError(t, err)
	// the directory and the pipe are file objects, so they reach OpenFiles and the exclusion below is tested there
	pid := int32(os.Getpid())
	require.Contains(t, snapshot.handles[pid], dirHandle.Fd(), "directory handle missing from the snapshot")
	require.Contains(t, snapshot.handles[pid], uintptr(pipe), "pipe handle missing from the snapshot")

	start := time.Now()
	files, err := snapshot.OpenFiles(context.Background(), pid)
	require.NoError(t, err)
	t.Logf("read %d open files in %s", len(files), time.Since(start))

	var matches []OpenFilesStat
	for _, f := range files {
		lower := strings.ToLower(f.Path)
		assert.False(t, strings.HasSuffix(lower, strings.ToLower(filepath.Base(dir))), "directory listed: %s", f.Path)
		assert.NotContains(t, lower, "gopsutil-open-files-test", "named pipe listed")
		if strings.HasSuffix(lower, `\open-file.txt`) {
			matches = append(matches, f)
		}
	}
	require.Len(t, matches, 1, "the open file is listed once: %+v", files)
	assert.Contains(t, []uint64{uint64(file.Fd()), uint64(again.Fd())}, matches[0].Fd,
		"Fd is not one of this process's handle values for the file")

	// the single-process path returns the same file
	p, err := NewProcess(pid)
	require.NoError(t, err)
	single, err := p.OpenFilesWithContext(context.Background())
	require.NoError(t, err)
	assert.Contains(t, single, matches[0])
}

// TestOpenFilesSnapshotWithoutReadAttributes checks that a file whose handle was opened without FILE_READ_ATTRIBUTES,
// as kernel and native-API callers often do, is still listed.
func TestOpenFilesSnapshotWithoutReadAttributes(t *testing.T) {
	waitFileQueriesIdle(t)
	filePath := filepath.Join(t.TempDir(), "write-only.txt")
	name, err := windows.NewNTUnicodeString(`\??\` + filePath)
	require.NoError(t, err)
	oa := windows.OBJECT_ATTRIBUTES{ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, windows.FILE_WRITE_DATA|windows.SYNCHRONIZE, &oa, &iosb, nil,
		windows.FILE_ATTRIBUTE_NORMAL, 0, windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	require.NoError(t, err)
	defer windows.CloseHandle(h)

	snapshot, err := NewOpenFilesSnapshot()
	require.NoError(t, err)
	files, err := snapshot.OpenFiles(context.Background(), int32(os.Getpid()))
	require.NoError(t, err)
	var found bool
	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f.Path), `\write-only.txt`) {
			found = true
			assert.Equal(t, uint64(h), f.Fd)
		}
	}
	assert.True(t, found, "file opened without FILE_READ_ATTRIBUTES not listed: %+v", files)
}

// TestOpenFilesSnapshotSkipsObjectInFlight checks that a handle to a file object a query is still running on is
// skipped without taking a query slot.
func TestOpenFilesSnapshotSkipsObjectInFlight(t *testing.T) {
	waitFileQueriesIdle(t)
	file, err := os.Create(filepath.Join(t.TempDir(), "in-flight.txt"))
	require.NoError(t, err)
	defer file.Close()

	snapshot, err := NewOpenFilesSnapshot()
	require.NoError(t, err)
	pid := int32(os.Getpid())
	var found bool
	var object uintptr
	for i, value := range snapshot.handles[pid] {
		if value == file.Fd() {
			found = true
			object = snapshot.objects[pid][i]
		}
	}
	require.True(t, found, "file handle missing from the snapshot")
	if object == 0 {
		t.Skip("the handle table does not report kernel object addresses to this process")
	}
	fileQueryObjects.Store(object, pid)
	t.Cleanup(func() { fileQueryObjects.Delete(object) })
	before := fileQueriesInFlight.Load()

	files, err := snapshot.OpenFiles(context.Background(), pid)
	require.NoError(t, err)
	for _, f := range files {
		assert.NotContains(t, strings.ToLower(f.Path), `\in-flight.txt`, "file with a query in flight listed")
	}
	// a query abandoned at its timeout may still be running; a slot the skipped handle took would never come back
	assert.Eventually(t, func() bool { return fileQueriesInFlight.Load() == before },
		5*time.Second, 10*time.Millisecond, "skipped handle took a query slot")
}

// TestOpenFilesSnapshotKeepsOneHandlePerObject checks that of several handles a process holds to one file object, the
// snapshot keeps only one.
func TestOpenFilesSnapshotKeepsOneHandlePerObject(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "shared-object.txt"))
	require.NoError(t, err)
	defer file.Close()
	dup := duplicateOwnHandle(t, file.Fd())
	defer windows.CloseHandle(dup)

	snapshot, err := NewOpenFilesSnapshot()
	require.NoError(t, err)
	pid := int32(os.Getpid())
	var kept int
	var object uintptr
	for i, value := range snapshot.handles[pid] {
		if value == file.Fd() || value == uintptr(dup) {
			kept++
			object = snapshot.objects[pid][i]
		}
	}
	require.NotZero(t, kept, "file handles missing from the snapshot")
	if object == 0 {
		t.Skip("the handle table does not report kernel object addresses to this process")
	}
	assert.Equal(t, 1, kept, "handles to one file object kept")
}

// TestRegularFilePathOfSaturated checks that once [maxFileQueriesInFlight] queries are outstanding, a handle is
// closed without starting another query and [ErrorFileQueriesSaturated] is returned, naming the pids the queries in
// flight were read through, and that the handle's file object and owner slot are released.
func TestRegularFilePathOfSaturated(t *testing.T) {
	tests := []struct {
		name   string
		object uintptr
		owner  int32
	}{
		{name: "no object or owner", object: 0, owner: 0},
		{name: "object and owner", object: 3, owner: 4243},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waitFileQueriesIdle(t)
			file, err := os.Create(filepath.Join(t.TempDir(), "skipped.txt"))
			require.NoError(t, err)
			defer file.Close()
			dup := duplicateOwnHandle(t, file.Fd())

			base := fileQueriesInFlight.Load()
			fileQueriesInFlight.Add(maxFileQueriesInFlight)
			t.Cleanup(func() { fileQueriesInFlight.Add(-maxFileQueriesInFlight) })
			// no kernel object lives at address 1, so this entry stands for a blocked query read through pid 4242
			fileQueryObjects.Store(uintptr(1), int32(4242))
			t.Cleanup(func() { fileQueryObjects.Delete(uintptr(1)) })

			path, ok, err := regularFilePathOf(context.Background(), dup, tt.object, tt.owner)
			require.ErrorIs(t, err, ErrorFileQueriesSaturated)
			assert.Contains(t, err.Error(), "blocked by pids [4242]")
			assert.False(t, ok)
			assert.Empty(t, path)
			assert.Equal(t, base+maxFileQueriesInFlight, fileQueriesInFlight.Load(), "skipped query kept a slot")
			if tt.object != 0 {
				_, held := fileQueryObjects.Load(tt.object)
				assert.False(t, held, "saturated query left its file object reserved")
			}
			fileQueryOwnersMu.Lock()
			assert.Zero(t, fileQueryOwners[tt.owner], "saturated query kept its owner slot")
			fileQueryOwnersMu.Unlock()
			assert.True(t, handleClosed(dup), "skipped handle left open")
		})
	}
}

// TestRegularFilePathOfAbandoned checks the lifecycle of a query that blocks: it is abandoned at [fileQueryTimeout]
// or when ctx is cancelled, keeps its slot, file object and owner slot while it runs, makes a second handle to the
// same object skip without taking a slot, and releases everything and closes its handle once it returns.
func TestRegularFilePathOfAbandoned(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		wantErr error
		minWait time.Duration
	}{
		{name: "timeout", ctx: context.Background(), wantErr: nil, minWait: fileQueryTimeout},
		{name: "cancelled", ctx: cancelled, wantErr: context.Canceled, minWait: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waitFileQueriesIdle(t)
			release := blockFileQueries(t)
			file, err := os.Create(filepath.Join(t.TempDir(), "blocked.txt"))
			require.NoError(t, err)
			defer file.Close()
			dup := duplicateOwnHandle(t, file.Fd())
			const object, owner = uintptr(2), int32(4242)
			base := fileQueriesInFlight.Load()

			start := time.Now()
			path, ok, err := regularFilePathOf(tt.ctx, dup, object, owner)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.False(t, ok)
			assert.Empty(t, path)
			assert.GreaterOrEqual(t, time.Since(start), tt.minWait)
			assert.Equal(t, base+1, fileQueriesInFlight.Load(), "abandoned query gave up its slot while still running")
			_, held := fileQueryObjects.Load(object)
			assert.True(t, held, "abandoned query released its file object while still running")
			fileQueryOwnersMu.Lock()
			assert.Equal(t, 1, fileQueryOwners[owner], "abandoned query released its owner slot while still running")
			fileQueryOwnersMu.Unlock()
			assert.False(t, handleClosed(dup), "abandoned query closed its handle while still running")

			// a second handle to the same object is skipped at once without taking a slot
			second := duplicateOwnHandle(t, file.Fd())
			start = time.Now()
			_, ok, err = regularFilePathOf(context.Background(), second, object, owner)
			require.NoError(t, err)
			assert.False(t, ok)
			assert.Less(t, time.Since(start), fileQueryTimeout, "handle to an object in flight was queried")
			assert.Equal(t, base+1, fileQueriesInFlight.Load(), "handle to an object in flight took a slot")
			assert.True(t, handleClosed(second), "skipped handle left open")

			release()
			require.Eventually(t, func() bool {
				_, held := fileQueryObjects.Load(object)
				fileQueryOwnersMu.Lock()
				owned := fileQueryOwners[owner]
				fileQueryOwnersMu.Unlock()
				return fileQueriesInFlight.Load() == base && !held && owned == 0 && handleClosed(dup)
			}, 5*time.Second, 10*time.Millisecond, "returned query did not release its slot, object, owner slot and handle")
		})
	}
}

// TestRegularFilePathOfOwnerShare checks that one owner's blocked queries hold at most [maxFileQueriesPerOwner]
// slots: a further handle of that owner is refused with [ErrorFileQueriesSaturated] naming the owner and takes no
// slot, while another owner still gets one.
func TestRegularFilePathOfOwnerShare(t *testing.T) {
	waitFileQueriesIdle(t)
	release := blockFileQueries(t)
	file, err := os.Create(filepath.Join(t.TempDir(), "owner.txt"))
	require.NoError(t, err)
	defer file.Close()
	const owner, other = int32(4242), int32(4244)
	base := fileQueriesInFlight.Load()

	for i := range maxFileQueriesPerOwner {
		_, _, err := regularFilePathOf(context.Background(), duplicateOwnHandle(t, file.Fd()), 0, owner)
		require.NoError(t, err, "query %d", i)
	}
	assert.Equal(t, base+maxFileQueriesPerOwner, fileQueriesInFlight.Load())

	extra := duplicateOwnHandle(t, file.Fd())
	start := time.Now()
	_, ok, err := regularFilePathOf(context.Background(), extra, 0, owner)
	require.ErrorIs(t, err, ErrorFileQueriesSaturated)
	assert.Contains(t, err.Error(), "blocked by pids [4242]")
	assert.False(t, ok)
	assert.Less(t, time.Since(start), fileQueryTimeout, "handle of an owner at its share was queried")
	assert.Equal(t, base+maxFileQueriesPerOwner, fileQueriesInFlight.Load(), "owner took more than its share")
	assert.True(t, handleClosed(extra), "skipped handle left open")

	_, _, err = regularFilePathOf(context.Background(), duplicateOwnHandle(t, file.Fd()), 0, other)
	require.NoError(t, err)
	assert.Equal(t, base+maxFileQueriesPerOwner+1, fileQueriesInFlight.Load(), "another owner was refused a slot")

	release()
	waitFileQueriesIdle(t)
}

// TestOpenFilesErrors checks the error contracts of [OpenFilesSnapshot.OpenFiles]: saturation and cancellation
// return the files read so far with the error, and a process that cannot be opened returns no files.
func TestOpenFilesErrors(t *testing.T) {
	waitFileQueriesIdle(t)
	pid := int32(os.Getpid())
	snapshot, err := NewOpenFilesSnapshot()
	require.NoError(t, err)
	require.NotEmpty(t, snapshot.handles[pid], "this process has no file handles in the snapshot")

	t.Run("saturated", func(t *testing.T) {
		fileQueriesInFlight.Add(maxFileQueriesInFlight)
		defer fileQueriesInFlight.Add(-maxFileQueriesInFlight)
		files, err := snapshot.OpenFiles(context.Background(), pid)
		require.ErrorIs(t, err, ErrorFileQueriesSaturated)
		assert.NotNil(t, files, "files read so far not returned")
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		files, err := snapshot.OpenFiles(ctx, pid)
		require.ErrorIs(t, err, context.Canceled)
		assert.NotNil(t, files, "files read so far not returned")
	})
	t.Run("process cannot be opened", func(t *testing.T) {
		// OpenProcess fails for the System Idle Process (pid 0)
		bad := &OpenFilesSnapshot{handles: map[int32][]uintptr{0: {4}}, objects: map[int32][]uintptr{0: {0}}}
		files, err := bad.OpenFiles(context.Background(), 0)
		require.Error(t, err)
		assert.Nil(t, files)
	})
	waitFileQueriesIdle(t)
}

// TestOpenFilesSnapshotKeepsOnlyFileHandles checks that the snapshot drops handles to objects other than files, so
// they are never duplicated, while keeping this process's file handle.
func TestOpenFilesSnapshotKeepsOnlyFileHandles(t *testing.T) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	require.NoError(t, err)
	defer windows.CloseHandle(event)
	file, err := os.Create(filepath.Join(t.TempDir(), "kept.txt"))
	require.NoError(t, err)
	defer file.Close()

	snapshot, err := NewOpenFilesSnapshot()
	require.NoError(t, err)
	own := snapshot.handles[int32(os.Getpid())]
	assert.NotContains(t, own, uintptr(event), "event handle kept")
	assert.Contains(t, own, file.Fd(), "file handle dropped")
}

// TestOpenFilesSnapshotUnknownPid checks that a pid with no file handles in the snapshot yields no files and no error.
func TestOpenFilesSnapshotUnknownPid(t *testing.T) {
	snapshot, err := NewOpenFilesSnapshot()
	require.NoError(t, err)
	files, err := snapshot.OpenFiles(context.Background(), -2)
	require.NoError(t, err)
	assert.Empty(t, files)
}

// TestReadHandleTableWithin checks the buffer sizing of [readHandleTableWithin] against a fake table query: growth on
// a length mismatch, growth by half when no size is reported, the bound, truncation to the size read, the clamp of a
// size hint above the bound, and that only a successful read stores the hint.
func TestReadHandleTableWithin(t *testing.T) {
	const minSize, maxSize = 64, 1024
	const accessDenied = common.NtStatus(0xC0000022)

	// reply is one answer of the fake table query: the status it returns and the size it reports as needed.
	type reply struct {
		status common.NtStatus
		needed uint32
	}
	tests := []struct {
		name      string
		hint      uint32
		replies   []reply
		wantSizes []uint32
		wantLen   int
		wantErr   bool
		wantHint  uint32
	}{
		{
			name:      "first read succeeds",
			replies:   []reply{{0, 50}},
			wantSizes: []uint32{minSize + minSize/8},
			wantLen:   50,
			wantHint:  50,
		},
		{
			name:      "grows to the reported size",
			replies:   []reply{{common.STATUS_INFO_LENGTH_MISMATCH, 200}, {0, 190}},
			wantSizes: []uint32{minSize + minSize/8, 200 + 200/8},
			wantLen:   190,
			wantHint:  190,
		},
		{
			name:      "grows by half when no size is reported",
			replies:   []reply{{common.STATUS_BUFFER_TOO_SMALL, 0}, {0, 70}},
			wantSizes: []uint32{minSize + minSize/8, 96 + 96/8},
			wantLen:   70,
			wantHint:  70,
		},
		{
			name:      "stops at the bound",
			replies:   []reply{{common.STATUS_INFO_LENGTH_MISMATCH, maxSize + 1}},
			wantSizes: []uint32{minSize + minSize/8},
			wantErr:   true,
		},
		{
			name:      "clamps a hint above the bound",
			hint:      maxSize + maxSize/8,
			replies:   []reply{{0, 1000}},
			wantSizes: []uint32{maxSize + maxSize/8},
			wantLen:   1000,
			wantHint:  1000,
		},
		{
			name:      "an error keeps the hint",
			hint:      300,
			replies:   []reply{{accessDenied, 0}},
			wantSizes: []uint32{300 + 300/8},
			wantErr:   true,
			wantHint:  300,
		},
	}
	savedHint := handleTableSizeHint.Load()
	savedQuery := queryHandleTable
	t.Cleanup(func() {
		queryHandleTable = savedQuery
		handleTableSizeHint.Store(savedHint)
	})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handleTableSizeHint.Store(tt.hint)
			var sizes []uint32
			queryHandleTable = func(_ *byte, size uint32, needed *uint32) common.NtStatus {
				r := tt.replies[min(len(sizes), len(tt.replies)-1)]
				sizes = append(sizes, size)
				*needed = r.needed
				return r.status
			}
			table, err := readHandleTableWithin(minSize, maxSize)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, table, tt.wantLen)
			}
			assert.Equal(t, tt.wantSizes, sizes, "buffer sizes passed to the query")
			assert.Equal(t, tt.wantHint, handleTableSizeHint.Load(), "stored size hint")
		})
	}
}

// TestHandleTableEntries checks that the entries read from a handle table are bounded by the buffer, whatever count
// its header reports.
func TestHandleTableEntries(t *testing.T) {
	var header common.SystemExtendedHandleInformation
	headerSize := int(unsafe.Offsetof(header.Handles))
	entrySize := int(unsafe.Sizeof(header.Handles[0]))

	tests := []struct {
		name      string
		bufSize   int
		claimed   uintptr
		wantCount int
	}{
		{name: "shorter than the header", bufSize: headerSize - 1, claimed: 5, wantCount: 0},
		{name: "count matches the buffer", bufSize: headerSize + 3*entrySize, claimed: 3, wantCount: 3},
		{name: "count larger than the buffer", bufSize: headerSize + 2*entrySize, claimed: 1000, wantCount: 2},
		{name: "partial trailing entry", bufSize: headerSize + 2*entrySize + entrySize/2, claimed: 3, wantCount: 2},
		{name: "empty table", bufSize: headerSize + entrySize, claimed: 0, wantCount: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// back the buffer with uintptr words so the header and entries are aligned
			words := make([]uintptr, (tt.bufSize+int(unsafe.Sizeof(uintptr(0)))-1)/int(unsafe.Sizeof(uintptr(0)))+1)
			buf := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), tt.bufSize)
			if tt.bufSize >= headerSize {
				(*common.SystemExtendedHandleInformation)(unsafe.Pointer(&buf[0])).NumberOfHandles = tt.claimed
			}
			assert.Len(t, handleTableEntries(buf), tt.wantCount)
		})
	}
}
