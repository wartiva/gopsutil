// SPDX-License-Identifier: BSD-3-Clause
//go:build windows

package process

import (
	"context"
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

// TestOpenFilesSnapshot checks that a snapshot lists this process's open regular file once, with its handle value,
// and leaves out a directory and a named pipe it also holds open.
func TestOpenFilesSnapshot(t *testing.T) {
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

	start := time.Now()
	files, err := snapshot.OpenFiles(context.Background(), int32(os.Getpid()))
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
	assert.NotZero(t, matches[0].Fd)

	// the single-process path returns the same file
	p, err := NewProcess(int32(os.Getpid()))
	require.NoError(t, err)
	single, err := p.OpenFilesWithContext(context.Background())
	require.NoError(t, err)
	assert.Contains(t, single, matches[0])
}

// TestOpenFilesSnapshotWithoutReadAttributes checks that a file whose handle was opened without FILE_READ_ATTRIBUTES,
// as kernel and native-API callers often do, is still listed.
func TestOpenFilesSnapshotWithoutReadAttributes(t *testing.T) {
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
	file, err := os.Create(filepath.Join(t.TempDir(), "in-flight.txt"))
	require.NoError(t, err)
	defer file.Close()

	snapshot, err := NewOpenFilesSnapshot()
	require.NoError(t, err)
	pid := int32(os.Getpid())
	var object uintptr
	for i, value := range snapshot.handles[pid] {
		if value == file.Fd() {
			object = snapshot.objects[pid][i]
		}
	}
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
	assert.Equal(t, before, fileQueriesInFlight.Load(), "skipped handle took a query slot")
}

// TestOpenFilesSnapshotKeepsOneHandlePerObject checks that of several handles a process holds to one file object, the
// snapshot keeps only one.
func TestOpenFilesSnapshotKeepsOneHandlePerObject(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "shared-object.txt"))
	require.NoError(t, err)
	defer file.Close()
	var dup windows.Handle
	require.NoError(t, windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()),
		windows.CurrentProcess(), &dup, 0, false, windows.DUPLICATE_SAME_ACCESS))
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
	if object == 0 {
		t.Skip("the handle table does not report kernel object addresses to this process")
	}
	assert.Equal(t, 1, kept, "handles to one file object kept")
}

// TestRegularFilePathSkipsWhenQueriesFull checks that once [maxFileQueriesInFlight] queries are outstanding, a handle
// is closed without starting another query and [ErrorFileQueriesSaturated] is returned, naming the pids the queries
// in flight were read through.
func TestRegularFilePathSkipsWhenQueriesFull(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "skipped.txt"))
	require.NoError(t, err)
	defer file.Close()
	var dup windows.Handle
	require.NoError(t, windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()),
		windows.CurrentProcess(), &dup, 0, false, windows.DUPLICATE_SAME_ACCESS))

	fileQueriesInFlight.Add(maxFileQueriesInFlight)
	t.Cleanup(func() { fileQueriesInFlight.Add(-maxFileQueriesInFlight) })
	// no kernel object lives at address 1, so this entry stands for a blocked query read through pid 4242
	fileQueryObjects.Store(uintptr(1), int32(4242))
	t.Cleanup(func() { fileQueryObjects.Delete(uintptr(1)) })

	path, ok, err := regularFilePath(context.Background(), dup)
	require.ErrorIs(t, err, ErrorFileQueriesSaturated)
	assert.Contains(t, err.Error(), "blocked by pids [4242]")
	assert.False(t, ok)
	assert.Empty(t, path)
	assert.Equal(t, int32(maxFileQueriesInFlight), fileQueriesInFlight.Load(), "skipped query kept a slot")
	_, err = windows.GetFileType(dup)
	assert.ErrorIs(t, err, windows.ERROR_INVALID_HANDLE, "skipped handle left open")
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
