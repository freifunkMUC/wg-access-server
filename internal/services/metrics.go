package services

import (
    "net/http"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/collectors"
    "github.com/prometheus/client_golang/prometheus/promhttp"

    "github.com/freifunkMUC/wg-access-server/buildinfo"
    "github.com/freifunkMUC/wg-access-server/internal/config"
    "github.com/freifunkMUC/wg-access-server/internal/devices"
)

type MetricsDeps struct {
    Config        *config.AppConfig
    DeviceManager *devices.DeviceManager
}

// MetricsHandler returns an http.Handler that exposes Prometheus metrics.
// It honors EnableMetadata by including device-specific metrics when enabled,
// but still exposes basic process/go/build metrics.
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

    // Device-related metrics (included when metadata enabled)
    if deps.DeviceManager != nil && deps.Config.EnableMetadata {
        // Total devices stored
        devicesTotal := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
            Namespace: "wg_access_server",
            Name:      "devices_total",
            Help:      "Total number of devices registered in storage.",
        }, func() float64 {
            devs, err := deps.DeviceManager.ListAllDevices()
            if err != nil {
                return 0
            }
            return float64(len(devs))
        })
        reg.MustRegister(devicesTotal)

        // Connected devices (based on last handshake)
        devicesConnected := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
            Namespace: "wg_access_server",
            Name:      "devices_connected",
            Help:      "Number of devices considered connected (recent handshake).",
        }, func() float64 {
            devs, err := deps.DeviceManager.ListAllDevices()
            if err != nil {
                return 0
            }
            var c int
            for _, d := range devs {
                if d.LastHandshakeTime != nil && devices.IsConnected(*d.LastHandshakeTime) {
                    c++
                }
            }
            return float64(c)
        })
        reg.MustRegister(devicesConnected)

        // Aggregate bytes received/transmitted across all devices
        rxBytesTotal := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
            Namespace: "wg_access_server",
            Name:      "devices_bytes_received_total",
            Help:      "Sum of received bytes across all devices (as tracked).",
        }, func() float64 {
            devs, err := deps.DeviceManager.ListAllDevices()
            if err != nil {
                return 0
            }
            var sum int64
            for _, d := range devs {
                sum += d.ReceiveBytes
            }
            return float64(sum)
        })
        reg.MustRegister(rxBytesTotal)

        txBytesTotal := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
            Namespace: "wg_access_server",
            Name:      "devices_bytes_transmitted_total",
            Help:      "Sum of transmitted bytes across all devices (as tracked).",
        }, func() float64 {
            devs, err := deps.DeviceManager.ListAllDevices()
            if err != nil {
                return 0
            }
            var sum int64
            for _, d := range devs {
                sum += d.TransmitBytes
            }
            return float64(sum)
        })
        reg.MustRegister(txBytesTotal)
    }

    return promhttp.HandlerFor(reg, promhttp.HandlerOpts{EnableOpenMetrics: true})
}
