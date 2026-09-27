package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// BenchmarkScrape is what a Prometheus scrape costs: every device is read and
// turned into series, once per scrape and per replica.
func BenchmarkScrape(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		for _, perDevice := range []bool{false, true} {
			name := fmt.Sprintf("%d-devices", count)
			if perDevice {
				name += "-with-device-series"
			}
			b.Run(name, func(b *testing.B) {
				s := storage.NewMemoryStorage()
				if err := s.Open(); err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = s.Close() })
				now := time.Now()
				for i := range count {
					device := &storage.Device{
						Owner: fmt.Sprintf("user-%d", i%50), Name: fmt.Sprintf("device-%d", i),
						PublicKey: fmt.Sprintf("key-%d", i), Address: fmt.Sprintf("10.44.%d.%d/32", i/256, i%256),
						ReceiveBytes: int64(i), TransmitBytes: int64(i * 2), LastHandshakeTime: &now,
					}
					if err := s.Save(device); err != nil {
						b.Fatal(err)
					}
				}
				dm := devices.New(noopWireGuardInterface{}, s, "10.44.0.0/16", "")
				maxSeries := 0
				if perDevice {
					maxSeries = -1 // every device gets its own series
				}
				deps := &Deps{
					DeviceManager: dm,
					Metadata:      true,
					DeviceMetrics: perDevice,
					Metrics:       config.MetricsConfig{MaxDeviceSeries: maxSeries},
				}
				handler := Handler(deps)
				b.ResetTimer()
				for range b.N {
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
					if rec.Code != http.StatusOK {
						b.Fatalf("scrape failed: %d", rec.Code)
					}
				}
			})
		}
	}
}
