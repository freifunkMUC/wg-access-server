package authutil

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/sirupsen/logrus"
)

// RandomString returns a base64url-encoded string of random data of size bytes
func RandomString(size int) string {
	blk := make([]byte, size)
	_, err := rand.Read(blk)
	if err != nil {
		logrus.Fatal(fmt.Errorf("failed to make a random string: %w", err))
	}
	return base64.URLEncoding.EncodeToString(blk)
}
