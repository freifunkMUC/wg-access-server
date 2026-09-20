//go:build linux

package hooks

import (
	"io/fs"
	"syscall"
)

// fileOwner returns the uid that owns the file.
func fileOwner(info fs.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
