// Command seedmany fills a database with many devices, to measure what the
// server's start-up costs when it has to bring them all up as peers.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

func key(i int) string {
	var k [32]byte
	binary.LittleEndian.PutUint64(k[:], uint64(i)+1)
	// a WireGuard key has its last byte clamped; any 32 bytes parse
	return base64.StdEncoding.EncodeToString(k[:])
}

func main() {
	uri := flag.String("storage", "", "storage URI")
	count := flag.Int("count", 5000, "how many devices")
	flag.Parse()
	logrus.SetLevel(logrus.WarnLevel)

	s, err := storage.NewStorage(*uri)
	if err != nil {
		logrus.Fatal(err)
	}
	if err := s.Open(); err != nil {
		logrus.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	for i := range *count {
		device := &storage.Device{
			Owner: fmt.Sprintf("user-%d", i%100), OwnerName: fmt.Sprintf("user-%d", i%100), OwnerProvider: "simple",
			Name: fmt.Sprintf("device-%d", i), PublicKey: key(i),
			Address: fmt.Sprintf("10.44.%d.%d/32, fd48:4c4:7aa9::%x/128", (i+2)/254, (i+2)%254, i+2),
		}
		if err := s.Save(device); err != nil {
			logrus.Fatal(err)
		}
	}
	fmt.Printf("%d Geräte gespeichert\n", *count)
}
