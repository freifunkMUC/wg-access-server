// Command seed fills a database with the devices the README screenshots
// show. It writes through the storage package, so the server finds exactly
// what it would have stored itself - including traffic and a recent handshake,
// which only a running WireGuard interface would produce otherwise.
//
// It is run by website/scripts/screenshots.mjs.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// key derives a stable public key from a name, so that the devices look the
// same on every run.
func key(name string) string {
	var k [32]byte
	copy(k[:], name)
	return base64.StdEncoding.EncodeToString(k[:])
}

func main() {
	uri := flag.String("storage", "", "storage URI, e.g. sqlite3:///tmp/screenshots.db")
	owner := flag.String("owner", "admin", "the user the devices belong to")
	flag.Parse()

	s, err := storage.NewStorage(*uri)
	if err != nil {
		logrus.Fatal(err)
	}
	if err := s.Open(); err != nil {
		logrus.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	now := time.Now()
	for i, name := range []string{"Home PC", "Laptop", "iPhone"} {
		device := &storage.Device{
			Owner:         *owner,
			OwnerName:     *owner,
			OwnerProvider: "simple",
			Name:          name,
			PublicKey:     key(name),
			Address:       fmt.Sprintf("10.44.0.%d/32, fd48:4c4:7aa9::%d/128", i+2, i+2),
			CreatedAt:     now.Add(-time.Duration(3-i) * 24 * time.Hour),
		}
		if err := s.Save(device); err != nil {
			logrus.Fatal(err)
		}
	}

	// The phone is connected: it talked to the server a moment ago. The
	// endpoint is from the documentation range (RFC 5737), not a real one.
	err = s.RecordMetadata([]storage.MetadataUpdate{{
		PublicKey:     key("iPhone"),
		ReceiveBytes:  1_014_000,
		TransmitBytes: 24_380_000,
		Connection: &storage.PeerConnection{
			Endpoint:          "203.0.113.42:51820",
			LastHandshakeTime: now.Add(-50 * time.Second),
		},
	}})
	if err != nil {
		logrus.Fatal(err)
	}
}
