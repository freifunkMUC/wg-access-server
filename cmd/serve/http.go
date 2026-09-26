package serve

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/api"
	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/metrics"
	"github.com/freifunkMUC/wg-access-server/internal/services"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
)

// How long a client may take. Without these, a client that sends its request
// a byte at a time holds on to a connection for as long as it likes, and
// enough of them use up the server's connections for everybody else
// (Slowloris). Nothing the web UI sends or receives takes long: the requests
// are small, and no response is streamed.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	idleTimeout       = 2 * time.Minute
)

// newRouter builds the web server: the endpoints anyone may reach, and behind the
// authentication middleware the API and the web UI.
func newRouter(conf *config.AppConfig, deviceManager *devices.DeviceManager, storageBackend storage.Storage, wg wgembed.WireGuardInterface) (http.Handler, error) {
	router := mux.NewRouter()
	router.Use(services.TracesMiddleware)
	router.Use(services.RecoveryMiddleware)
	router.Use(services.SecurityHeadersMiddleware)
	router.Use(audit.Middleware)
	// Refuses a POST (or PUT, DELETE, ...) a browser sends on behalf of
	// another site: signing in or out, and the API. Scripts send no such
	// headers and are not affected.
	router.Use(http.NewCrossOriginProtection().Handler)

	// Health check endpoint
	router.PathPrefix("/health").Handler(services.HealthEndpoint(deviceManager))

	// Prometheus metrics endpoint (optionally basic-auth protected)
	router.Path("/metrics").Handler(metrics.Endpoint(&metrics.Deps{
		Config:        conf,
		DeviceManager: deviceManager,
	}))

	// Authentication middleware
	claims := authnz.ClaimsMiddleware(conf)
	middleware, err := authnz.NewMiddleware(conf.Auth, claims)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set up authnz middleware")
	}
	router.Use(middleware)

	// API tokens, after the session: a request that names a token acts as it
	// (and the middleware refuses every token while they are disabled)
	tokens := apitokens.New(storageBackend, claims)
	var acceptedTokens *apitokens.Manager
	if conf.EnableAPITokens {
		acceptedTokens = tokens
	}
	router.Use(apitokens.Middleware(acceptedTokens))

	// Subrouter for our site (web + api)
	site := router.PathPrefix("/").Subrouter()
	site.Use(authnz.RequireAuthentication)

	apiServices := &api.Services{
		Config:        conf,
		DeviceManager: deviceManager,
		Tokens:        tokens,
		Wg:            wg,
	}

	// API
	site.PathPrefix("/api").Handler(http.StripPrefix("/api", api.Router(apiServices)))

	// Static website
	site.PathPrefix("/").Handler(services.WebsiteRouter())

	return router, nil
}

// listenAndServe serves the web UI until a signal arrives or a listener fails.
// stopBackground runs before the servers are shut down.
func listenAndServe(conf *config.AppConfig, handler http.Handler, stopBackground func()) error {
	signalChan := make(chan os.Signal, 2)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	errChan := make(chan error)

	// Listen
	var httpSrv *http.Server
	if conf.HttpEnabled {
		address := fmt.Sprintf("%s:%d", conf.HttpHost, conf.Port)

		httpSrv = &http.Server{
			Addr:              address,
			Handler:           handler,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			IdleTimeout:       idleTimeout,
		}

		go func() {
			logrus.Infof("Web UI listening on http://%v", address)
			err := httpSrv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- errors.Wrap(err, "unable to start http server")
			}
		}()
	}

	var httpsSrv *http.Server
	if conf.HTTPS.Enabled {
		httpsAddress := fmt.Sprintf("%s:%d", conf.HTTPS.Host, conf.HTTPS.Port)

		certPath := conf.HTTPS.CertFile
		keyPath := conf.HTTPS.KeyFile
		if certPath == "" || keyPath == "" {
			certPath, keyPath = services.GetDefaultCertPaths()
		}

		tlsConfig, err := services.LoadTLSCert(certPath, keyPath, services.CertHosts(conf.ExternalHost))
		if err != nil {
			return errors.Wrap(err, "failed to load TLS certificate")
		}

		httpsSrv = &http.Server{
			Addr:      httpsAddress,
			Handler:   handler,
			TLSConfig: tlsConfig,
			// see readHeaderTimeout
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			IdleTimeout:       idleTimeout,
		}

		go func() {
			logrus.Infof("Web UI listening on https://%v", httpsAddress)
			err := httpsSrv.ListenAndServeTLS("", "") // Cert and key are already in TLSConfig
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- errors.Wrap(err, "unable to start https server")
			}
		}()
	}

	select {
	case <-signalChan:
		logrus.Info("shutting down server...")
		stopBackground()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if httpSrv != nil {
			if err := httpSrv.Shutdown(ctx); err != nil {
				logrus.Error(errors.Wrap(err, "unable to shutdown http server"))
			}
		}
		if httpsSrv != nil {
			if err := httpsSrv.Shutdown(ctx); err != nil {
				logrus.Error(errors.Wrap(err, "unable to shutdown https server"))
			}
		}
		return nil
	case err := <-errChan:
		return err
	}
}
