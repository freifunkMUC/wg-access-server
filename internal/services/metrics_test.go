package services

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// noopWireGuardInterface satisfies wgembed.WireGuardInterface without
// touching real network/kernel state.
type noopWireGuardInterface struct{}

func (noopWireGuardInterface) LoadConfig(*wgembed.ConfigFile) error   { return nil }
func (noopWireGuardInterface) AddPeer(string, string, []string) error { return nil }
func (noopWireGuardInterface) ListPeers() ([]wgtypes.Peer, error)     { return nil, nil }
func (noopWireGuardInterface) RemovePeer(string) error                { return nil }
func (noopWireGuardInterface) PublicKey() (string, error)             { return "", nil }
func (noopWireGuardInterface) Close() error                           { return nil }
func (noopWireGuardInterface) Ping() error                            { return nil }

// failingStorage wraps in-memory storage and fails every List call, to
// exercise the scrape error path.
type failingStorage struct {
	storage.Storage
}

func (failingStorage) List(string) ([]*storage.Device, error) {
	return nil, errors.New("storage unavailable")
}

func newDeviceManager(t *testing.T) (*devices.DeviceManager, storage.Storage) {
	t.Helper()
	s := storage.NewMemoryStorage()
	return devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", ""), s
}

func metricsDeps(dm *devices.DeviceManager, deviceMetrics bool, maxSeries int) *MetricsDeps {
	conf := &config.AppConfig{EnableMetadata: true, EnableDeviceMetrics: deviceMetrics}
	conf.Metrics.MaxDeviceSeries = maxSeries
	return &MetricsDeps{Config: conf, DeviceManager: dm}
}

func scrapeMetrics(t *testing.T, deps *MetricsDeps) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	MetricsHandler(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	return rec.Body.String()
}

func saveDevice(t *testing.T, s storage.Storage, device *storage.Device) {
	t.Helper()
	if err := s.Save(device); err != nil {
		t.Fatalf("seed device: %v", err)
	}
}

func assertContains(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("expected metrics output to contain %q, got:\n%s", w, body)
		}
	}
}

func TestDeviceMetrics_Disabled(t *testing.T) {
	dm, _ := newDeviceManager(t)

	body := scrapeMetrics(t, metricsDeps(dm, false, DefaultMaxDeviceSeries))

	if strings.Contains(body, "wg_access_server_device") {
		t.Fatalf("expected no device metrics when EnableDeviceMetrics is false, got:\n%s", body)
	}
}

func TestDeviceMetrics_PerDevice(t *testing.T) {
	dm, s := newDeviceManager(t)

	recent := time.Now()
	stale := time.Now().Add(-1 * time.Hour)

	saveDevice(t, s, &storage.Device{
		Owner: "user-a", Name: "laptop-1",
		ReceiveBytes: 100, TransmitBytes: 200,
		LastHandshakeTime: &recent,
	})
	saveDevice(t, s, &storage.Device{
		Owner: "user-b", Name: "phone-1",
		ReceiveBytes: 50, TransmitBytes: 25,
		LastHandshakeTime: &stale,
	})

	body := scrapeMetrics(t, metricsDeps(dm, true, DefaultMaxDeviceSeries))

	assertContains(t, body,
		`wg_access_server_device_connected{device="laptop-1",owner="user-a"} 1`,
		`wg_access_server_device_connected{device="phone-1",owner="user-b"} 0`,
		`wg_access_server_device_bytes_received_total{device="laptop-1",owner="user-a"} 100`,
		`wg_access_server_device_bytes_transmitted_total{device="laptop-1",owner="user-a"} 200`,
		`wg_access_server_device_last_handshake_timestamp_seconds{device="laptop-1",owner="user-a"}`,
		// The aggregates keep working alongside the per-device series.
		"wg_access_server_devices_total 2",
		"wg_access_server_devices_connected 1",
		"wg_access_server_devices_bytes_received_total 150",
		"wg_access_server_devices_bytes_transmitted_total 225",
		"wg_access_server_device_metrics_scrape_error 0",
		"wg_access_server_device_metrics_series_dropped 0",
	)
}

func TestDeviceMetrics_SameNameDifferentOwnersAreDistinct(t *testing.T) {
	// Device Name is only unique per-owner, not globally. Including owner
	// in the label set keeps such devices as separate series instead of
	// colliding.
	dm, s := newDeviceManager(t)

	now := time.Now()
	saveDevice(t, s, &storage.Device{
		Owner: "user-a", Name: "phone",
		ReceiveBytes: 100, TransmitBytes: 100,
		LastHandshakeTime: &now,
	})
	saveDevice(t, s, &storage.Device{
		Owner: "user-b", Name: "phone",
		ReceiveBytes: 50, TransmitBytes: 25,
		LastHandshakeTime: &now,
	})

	body := scrapeMetrics(t, metricsDeps(dm, true, DefaultMaxDeviceSeries))

	assertContains(t, body,
		`wg_access_server_device_bytes_received_total{device="phone",owner="user-a"} 100`,
		`wg_access_server_device_bytes_received_total{device="phone",owner="user-b"} 50`,
	)
}

func TestDeviceMetrics_DeletedDeviceDropsOutOfScrape(t *testing.T) {
	dm, s := newDeviceManager(t)

	now := time.Now()
	device := &storage.Device{
		Owner: "user-a", Name: "temp-device",
		ReceiveBytes: 10, TransmitBytes: 10,
		LastHandshakeTime: &now,
	}
	saveDevice(t, s, device)

	deps := metricsDeps(dm, true, DefaultMaxDeviceSeries)

	before := scrapeMetrics(t, deps)
	if !strings.Contains(before, `device="temp-device"`) {
		t.Fatalf("expected device to be present before deletion, got:\n%s", before)
	}

	if err := s.Delete(device); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	after := scrapeMetrics(t, deps)
	if strings.Contains(after, `device="temp-device"`) {
		t.Fatalf("expected device to be gone after deletion, got:\n%s", after)
	}
}

func TestDeviceMetrics_SeriesCapDropsExcessDevices(t *testing.T) {
	dm, s := newDeviceManager(t)

	now := time.Now()
	for i := 0; i < 5; i++ {
		saveDevice(t, s, &storage.Device{
			Owner: "user-a", Name: fmt.Sprintf("device-%d", i),
			ReceiveBytes: 1, TransmitBytes: 1,
			LastHandshakeTime: &now,
		})
	}

	body := scrapeMetrics(t, metricsDeps(dm, true, 2))

	// The cap applies to the label sets, not to the aggregates.
	assertContains(t, body,
		"wg_access_server_devices_total 5",
		"wg_access_server_device_metrics_series_dropped 3",
		// Devices are sorted, so the retained ones are deterministic.
		`wg_access_server_device_connected{device="device-0",owner="user-a"} 1`,
		`wg_access_server_device_connected{device="device-1",owner="user-a"} 1`,
	)
	if strings.Contains(body, `device="device-2"`) {
		t.Errorf("expected device-2 to be dropped by the series cap, got:\n%s", body)
	}
}

func TestDeviceMetrics_ZeroCapKeepsAggregatesOnly(t *testing.T) {
	dm, s := newDeviceManager(t)

	now := time.Now()
	saveDevice(t, s, &storage.Device{
		Owner: "user-a", Name: "laptop",
		ReceiveBytes: 7, TransmitBytes: 9,
		LastHandshakeTime: &now,
	})

	deps := metricsDeps(dm, true, 0)
	// A zero value means "not configured" and must not silently disable the cap.
	if got := resolveMaxDeviceSeries(deps.Config.Metrics.MaxDeviceSeries); got != DefaultMaxDeviceSeries {
		t.Fatalf("expected zero to resolve to the default cap, got %d", got)
	}

	body := scrapeMetrics(t, deps)
	assertContains(t, body, "wg_access_server_devices_total 1")
}

func TestDeviceMetrics_NegativeCapIsUnlimited(t *testing.T) {
	dm, s := newDeviceManager(t)

	now := time.Now()
	for i := 0; i < 3; i++ {
		saveDevice(t, s, &storage.Device{
			Owner: "user-a", Name: fmt.Sprintf("device-%d", i),
			LastHandshakeTime: &now,
		})
	}

	body := scrapeMetrics(t, metricsDeps(dm, true, -1))

	assertContains(t, body,
		`device="device-0"`,
		`device="device-1"`,
		`device="device-2"`,
		"wg_access_server_device_metrics_series_dropped 0",
	)
}

func TestDeviceMetrics_HostileLabelValuesAreSanitized(t *testing.T) {
	dm, s := newDeviceManager(t)

	now := time.Now()
	longName := strings.Repeat("a", maxLabelValueLen+50)
	saveDevice(t, s, &storage.Device{
		Owner: "user-a", Name: longName,
		LastHandshakeTime: &now,
	})
	// Invalid UTF-8 would make the exposition unparseable for Prometheus.
	saveDevice(t, s, &storage.Device{
		Owner: "user-b", Name: "bad-\xff-name",
		LastHandshakeTime: &now,
	})
	// Quotes and newlines must be escaped, not break out of the label.
	saveDevice(t, s, &storage.Device{
		Owner: "user-c", Name: "evil\"} 1\nwg_access_server_up{x=\"",
		LastHandshakeTime: &now,
	})

	body := scrapeMetrics(t, metricsDeps(dm, true, DefaultMaxDeviceSeries))

	assertContains(t, body,
		fmt.Sprintf(`device="%s",owner="user-a"`, strings.Repeat("a", maxLabelValueLen)),
		`device="bad-�-name",owner="user-b"`,
	)
	if strings.Contains(body, "\nwg_access_server_up{x=") {
		t.Errorf("label value escaped its series, got:\n%s", body)
	}
	if strings.Contains(body, strings.Repeat("a", maxLabelValueLen+1)) {
		t.Errorf("expected the device name to be truncated, got:\n%s", body)
	}
}

func TestDeviceMetrics_SanitizedCollisionsDoNotFailTheScrape(t *testing.T) {
	// Two distinct names that only differ past the truncation limit collapse
	// onto one label set; emitting both would fail the whole scrape with a
	// duplicate series error.
	dm, s := newDeviceManager(t)

	now := time.Now()
	prefix := strings.Repeat("b", maxLabelValueLen)
	saveDevice(t, s, &storage.Device{Owner: "user-a", Name: prefix + "-one", LastHandshakeTime: &now})
	saveDevice(t, s, &storage.Device{Owner: "user-a", Name: prefix + "-two", LastHandshakeTime: &now})

	body := scrapeMetrics(t, metricsDeps(dm, true, DefaultMaxDeviceSeries))

	assertContains(t, body,
		"wg_access_server_devices_total 2",
		"wg_access_server_device_metrics_series_dropped 1",
	)
}

func TestDeviceMetrics_EmptyLabelValuesGetAPlaceholder(t *testing.T) {
	dm, s := newDeviceManager(t)

	now := time.Now()
	saveDevice(t, s, &storage.Device{Owner: "", Name: "orphan", LastHandshakeTime: &now})

	body := scrapeMetrics(t, metricsDeps(dm, true, DefaultMaxDeviceSeries))

	assertContains(t, body, fmt.Sprintf(`device="orphan",owner="%s"`, unknownLabelValue))
}

func TestDeviceMetrics_StorageErrorIsReportedNotZeroed(t *testing.T) {
	s := storage.NewMemoryStorage()
	dm := devices.New(noopWireGuardInterface{}, failingStorage{Storage: s}, "10.44.0.0/24", "")

	body := scrapeMetrics(t, metricsDeps(dm, true, DefaultMaxDeviceSeries))

	assertContains(t, body, "wg_access_server_device_metrics_scrape_error 1")
	// A storage failure must not be reported as "zero devices".
	if strings.Contains(body, "wg_access_server_devices_total") {
		t.Errorf("expected no device gauges on storage failure, got:\n%s", body)
	}
}

func TestDeviceMetrics_NoDeviceMetricsWithoutMetadata(t *testing.T) {
	dm, s := newDeviceManager(t)

	now := time.Now()
	saveDevice(t, s, &storage.Device{Owner: "user-a", Name: "laptop", LastHandshakeTime: &now})

	conf := &config.AppConfig{EnableMetadata: false, EnableDeviceMetrics: true}
	conf.Metrics.MaxDeviceSeries = DefaultMaxDeviceSeries

	body := scrapeMetrics(t, &MetricsDeps{Config: conf, DeviceManager: dm})

	if strings.Contains(body, "wg_access_server_device") {
		t.Fatalf("expected no device metrics without metadata collection, got:\n%s", body)
	}
}
