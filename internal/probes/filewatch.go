package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/loudmumble/sentinel/internal/config"
	"github.com/loudmumble/sentinel/internal/events"
	"golang.org/x/sys/unix"
)

// Inotify event masks
const (
	InAccess     = unix.IN_ACCESS
	InModify     = unix.IN_MODIFY
	InAttrib     = unix.IN_ATTRIB
	InCloseWrite = unix.IN_CLOSE_WRITE
	InCreate     = unix.IN_CREATE
	InDelete     = unix.IN_DELETE
	InMovedFrom  = unix.IN_MOVED_FROM
	InMovedTo    = unix.IN_MOVED_TO
	InDeleteSelf = unix.IN_DELETE_SELF
	InMoveSelf   = unix.IN_MOVE_SELF
)

// FileProbe monitors filesystem changes using inotify.
type FileProbe struct {
	Config  config.SentinelConfig
	Fd      int
	WdMap   map[int]string
	Running bool
	HasFd   bool
}

// NewFileProbe creates a FileProbe.
func NewFileProbe(cfg config.SentinelConfig) *FileProbe {
	return &FileProbe{
		Config: cfg,
		Fd:     -1,
		WdMap:  make(map[int]string),
	}
}

// Start initializes inotify and adds watches for configured paths.
func (f *FileProbe) Start() {
	fd, err := unix.InotifyInit()
	if err != nil {
		return
	}
	f.Fd = fd
	f.HasFd = true

	mask := uint32(InModify | InCreate | InDelete | InMovedFrom | InMovedTo)
	for _, path := range f.Config.WatchPaths {
		if _, err := os.Stat(path); err == nil {
			wd, err := unix.InotifyAddWatch(f.Fd, path, mask)
			if err == nil && wd >= 0 {
				f.WdMap[wd] = path
			}
		}
	}
	f.Running = true
}

// Stop closes the inotify file descriptor.
func (f *FileProbe) Stop() {
	f.Running = false
	if f.HasFd {
		unix.Close(f.Fd)
		f.Fd = -1
		f.HasFd = false
	}
}

// Poll reads pending inotify events.
func (f *FileProbe) Poll() []events.EventInterface {
	var evts []events.EventInterface
	if !f.Running || !f.HasFd {
		return evts
	}

	// Use select to check if data is available (non-blocking)
	fds := &unix.FdSet{}
	fds.Bits[f.Fd/64] |= 1 << (uint(f.Fd) % 64)

	tv := unix.Timeval{Sec: 0, Usec: 0}
	n, err := unix.Select(f.Fd+1, fds, nil, nil, &tv)
	if err != nil || n <= 0 {
		return evts
	}

	buf := make([]byte, 4096)
	n2, err := unix.Read(f.Fd, buf)
	if err != nil || n2 <= 0 {
		return evts
	}

	offset := 0
	for offset < n2 {
		if offset+unix.SizeofInotifyEvent > n2 {
			break
		}
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
		nameLen := int(raw.Len)
		name := ""
		if nameLen > 0 && offset+unix.SizeofInotifyEvent+nameLen <= n2 {
			nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+nameLen]
			// Trim null bytes
			for i, b := range nameBytes {
				if b == 0 {
					nameBytes = nameBytes[:i]
					break
				}
			}
			name = string(nameBytes)
		}

		watchPath, ok := f.WdMap[int(raw.Wd)]
		if !ok {
			watchPath = "unknown"
		}
		fullPath := watchPath
		if name != "" {
			fullPath = filepath.Join(watchPath, name)
		}

		op := ""
		mask := raw.Mask
		if mask&unix.IN_CREATE != 0 {
			op = "create"
		} else if mask&unix.IN_DELETE != 0 {
			op = "delete"
		} else if mask&unix.IN_MODIFY != 0 {
			op = "modify"
		} else if mask&unix.IN_MOVED_FROM != 0 {
			op = "rename_from"
		} else if mask&unix.IN_MOVED_TO != 0 {
			op = "rename_to"
		}

		if op != "" {
			e := events.NewFileEvent()
			e.Path = fullPath
			e.Operation = op
			pid := 0
			uid := 0
			e.PID = &pid
			e.UID = &uid
			evts = append(evts, e)
		}

		offset += unix.SizeofInotifyEvent + nameLen
	}
	return evts
}

// String returns probe info.
func (f *FileProbe) String() string {
	return fmt.Sprintf("FileProbe(running=%v, watches=%d)", f.Running, len(f.WdMap))
}
