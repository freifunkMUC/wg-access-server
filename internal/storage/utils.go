package storage

import (
	"fmt"
)

// keyStr identifies a device in the in-memory storage. Both parts are quoted,
// so no owner or device name can produce the key of another owner's device -
// joining them as a path did, because "../bob/laptop" was cleaned to bob's.
func keyStr(owner string, name string) string {
	return fmt.Sprintf("%q/%q", owner, name)
}

func key(device *Device) string {
	return keyStr(device.Owner, device.Name)
}
