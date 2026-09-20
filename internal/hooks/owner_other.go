//go:build !linux

package hooks

import "io/fs"

// fileOwner has no portable implementation. The lifecycle commands are about
// configuring the VPN network, which only works on Linux anyway.
func fileOwner(info fs.FileInfo) (uint32, bool) {
	return 0, false
}
