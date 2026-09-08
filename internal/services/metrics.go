package services

import (
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/buildinfo"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

const (
	// DefaultMaxDeviceSeries is the per-device series cap applied when the
	// operator doesn't configure one. Device names and owners are attacker
	// controlled labels, so an uncapped export lets any user blow up the
	// cardinality of the scraping Prometheus.
	DefaultMaxDeviceSeries = 1000

	// maxLabelValueLen bounds the length of a user controlled label value.
	// Device names have no length limit in storage.
	maxLabelValueLen = 128

	// unknownLabelValue replaces empty label values so a series never carries
	// an empty identity.
	unknownLabelValue = "unknown"
)

type MetricsDeps struct {
	Config        *config.AppConfig
	DeviceManager *devices.DeviceManager
}

var (
	deviceLabels = []string{"device", "owner"}

	devicesTotalDesc = prometheus.NewDesc(
		"wg_access_server_devices_total",
		"Total number of devices registered in storage.",
		nil, nil,
	)
	devicesConnectedDesc = prometheus.NewDesc(
		"wg_access_server_devices_connected",
		"Number of devices considered connected (recent handshake).",
		nil, nil,
	)
	devicesBytesReceivedDesc = prometheus.NewDesc(
		"wg_access_server_devices_bytes_received_total",
		"Sum of received bytes across all devices (as tracked).",
		nil, nil,
	)
	devicesBytesTransmittedDesc = prometheus.NewDesc(
		"wg_access_server_devices_bytes_transmitted_total",
		"Sum of transmitted bytes across all devices (as tracked).",
		nil, nil,
	)

	deviceConnectedDesc = prometheus.NewDesc(
		"wg_access_server_device_connected",
		"1 if the device is considered connected (recent handshake), 0 otherwise.",
		deviceLabels, nil,
	)
	deviceBytesReceivedDesc = prometheus.NewDesc(
		"wg_access_server_device_bytes_received_total",
		"Received bytes for this device (as tracked).",
		deviceLabels, nil,
	)
	deviceBytesTransmittedDesc = prometheus.NewDesc(
		"wg_access_server_device_bytes_transmitted_total",
		"Transmitted bytes for this device (as tracked).",
		deviceLabels, nil,
	)
	deviceLastHandshakeDesc = prometheus.NewDesc(
		"wg_access_server_device_last_handshake_timestamp_seconds",
		"Unix timestamp of the device's last WireGuard handshake, if any.",
		deviceLabels, nil,
	)

	deviceScrapeErrorDesc = prometheus.NewDesc(
		"wg_access_server_device_metrics_scrape_error",
		"1 if the last scrape failed to read devices from storage, 0 otherwise.",
		nil, nil,
	)
	deviceSeriesDroppedDesc = prometheus.NewDesc(
		"wg_access_server_device_metrics_series_dropped",
		"Number of devices omitted from the per-device metrics in the last scrape (series cap or label collision).",
		nil, nil,
	)
)

// deviceCollector recomputes every device metric from storage on each scrape,
// so deleted devices don't leave stale series behind like a GaugeVec would.
// Listing devices once per scrape also keeps the endpoint from fanning a single
// unauthenticated request out into several storage queries.
type deviceCollector struct {
	deviceManager *devices.DeviceManager
	// maxSeries caps the number of devices exported with their own label set:
	// negative means unlimited, zero disables per-device metrics entirely.
	maxSeries int
}

func (c *deviceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- devicesTotalDesc
	ch <- devicesConnectedDesc
	ch <- devicesBytesReceivedDesc
	ch <- devicesBytesTransmittedDesc
	ch <- deviceScrapeErrorDesc

	if c.maxSeries == 0 {
		return
	}
	ch <- deviceConnectedDesc
	ch <- deviceBytesReceivedDesc
	ch <- deviceBytesTransmittedDesc
	ch <- deviceLastHandshakeDesc
	ch <- deviceSeriesDroppedDesc
}

func (c *deviceCollector) Collect(ch chan<- prometheus.Metric) {
	devs, err := c.deviceManager.ListAllDevices()
	if err != nil {
		// Reporting zeros here would be indistinguishable from "no devices",
		// so report the failure and export nothing else.
		logrus.Error(errors.Wrap(err, "failed to list devices while scraping metrics"))
		emitMetric(ch, deviceScrapeErrorDesc, 1)
		return
	}
	emitMetric(ch, deviceScrapeErrorDesc, 0)

	var connected int
	var receiveBytes, transmitBytes int64
	for _, d := range devs {
		if d.LastHandshakeTime != nil && devices.IsConnected(*d.LastHandshakeTime) {
			connected++
		}
		receiveBytes += d.ReceiveBytes
		transmitBytes += d.TransmitBytes
	}

	emitMetric(ch, devicesTotalDesc, float64(len(devs)))
	emitMetric(ch, devicesConnectedDesc, float64(connected))
	emitMetric(ch, devicesBytesReceivedDesc, float64(receiveBytes))
	emitMetric(ch, devicesBytesTransmittedDesc, float64(transmitBytes))

	if c.maxSeries != 0 {
		c.collectPerDevice(ch, devs)
	}
}

func (c *deviceCollector) collectPerDevice(ch chan<- prometheus.Metric, devs []*storage.Device) {
	// Storage backends don't guarantee an order (the in-memory map certainly
	// doesn't), so sort before applying the cap: which devices get dropped
	// must not flip from one scrape to the next.
	sorted := make([]*storage.Device, len(devs))
	copy(sorted, devs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Owner != sorted[j].Owner {
			return sorted[i].Owner < sorted[j].Owner
		}
		return sorted[i].Name < sorted[j].Name
	})

	seen := make(map[[2]string]struct{}, len(sorted))
	dropped := 0

	for _, d := range sorted {
		// Device Name is only unique per-owner, so owner has to be part of the
		// label set for two users' "phone" to stay separate series.
		labels := [2]string{sanitizeLabelValue(d.Name), sanitizeLabelValue(d.Owner)}

		// Sanitizing can map two distinct devices onto the same label set;
		// emitting both would fail the whole scrape with a duplicate series.
		if _, duplicate := seen[labels]; duplicate {
			dropped++
			continue
		}
		if c.maxSeries > 0 && len(seen) >= c.maxSeries {
			dropped++
			continue
		}
		seen[labels] = struct{}{}

		connected := 0.0
		if d.LastHandshakeTime != nil && devices.IsConnected(*d.LastHandshakeTime) {
			connected = 1
		}

		emitMetric(ch, deviceConnectedDesc, connected, labels[0], labels[1])
		emitMetric(ch, deviceBytesReceivedDesc, float64(d.ReceiveBytes), labels[0], labels[1])
		emitMetric(ch, deviceBytesTransmittedDesc, float64(d.TransmitBytes), labels[0], labels[1])
		if d.LastHandshakeTime != nil {
			emitMetric(ch, deviceLastHandshakeDesc, float64(d.LastHandshakeTime.Unix()), labels[0], labels[1])
		}
	}

	emitMetric(ch, deviceSeriesDroppedDesc, float64(dropped))
}

// emitMetric is a non-panicking MustNewConstMetric. The registry gathers
// collectors on their own goroutines, where a panic would take the process
// down instead of being caught by RecoveryMiddleware.
func emitMetric(ch chan<- prometheus.Metric, desc *prometheus.Desc, value float64, labelValues ...string) {
	metric, err := prometheus.NewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
	if err != nil {
		logrus.Error(errors.Wrapf(err, "failed to build metric %s", desc))
		return
	}
	ch <- metric
}

// sanitizeLabelValue bounds a user controlled label value. Device names are
// accepted verbatim from the API, and neither the text nor the OpenMetrics
// exposition format can carry invalid UTF-8.
func sanitizeLabelValue(value string) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "�")
	}
	value = truncateUTF8(value, maxLabelValueLen)
	if value == "" {
		return unknownLabelValue
	}
	return value
}

func truncateUTF8(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	truncated := value[:maxBytes]
	// Cutting at a fixed byte offset can split a rune; trim back to a boundary.
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

// resolveMaxDeviceSeries maps the configured value onto the collector's
// semantics, treating the zero value as "not configured".
func resolveMaxDeviceSeries(configured int) int {
	if configured == 0 {
		return DefaultMaxDeviceSeries
	}
	return configured
}

// MetricsHandler returns an http.Handler that exposes Prometheus metrics.
// Device metrics are only registered when both metadata collection and device
// metrics are enabled, but process/build metrics are always exposed.
func MetricsHandler(deps *MetricsDeps) http.Handler {
	reg := prometheus.NewRegistry()

	// Standard process and Go runtime collectors
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector())

	// Build info gauge with labels {version, commit}
	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "wg_access_server",
		Name:      "build_info",
		Help:      "Build information for wg-access-server.",
		ConstLabels: prometheus.Labels{
			"version": buildinfo.Version(),
			"commit":  buildinfo.ShortCommitHash(),
		},
	})
	buildInfo.Set(1)
	reg.MustRegister(buildInfo)

	// Up metric based on DeviceManager Ping (storage+wg reachability)
	up := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "wg_access_server",
		Name:      "up",
		Help:      "1 if core dependencies are reachable (storage and WireGuard).",
	}, func() float64 {
		if deps.DeviceManager == nil {
			return 0
		}
		if err := deps.DeviceManager.Ping(); err != nil {
			return 0
		}
		return 1
	})
	reg.MustRegister(up)

	// Device-related metrics (included when metadata + device metrics enabled)
	if deps.DeviceManager != nil && deps.Config.EnableMetadata && deps.Config.EnableDeviceMetrics {
		reg.MustRegister(&deviceCollector{
			deviceManager: deps.DeviceManager,
			maxSeries:     resolveMaxDeviceSeries(deps.Config.Metrics.MaxDeviceSeries),
		})
	}

	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{EnableOpenMetrics: true})
}

// MetricsEndpoint wraps MetricsHandler with optional basic auth protection.
func MetricsEndpoint(deps *MetricsDeps) http.Handler {
	h := MetricsHandler(deps)
	creds := deps.Config.Metrics.BasicAuth
	if creds.Username == "" || creds.PasswordHash == "" {
		return h
	}
	return basicAuthHandler(h, "metrics", creds.Username, creds.PasswordHash)
}
