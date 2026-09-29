package serve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/api"
	"github.com/freifunkMUC/wg-access-server/internal/apitokens"
	"github.com/freifunkMUC/wg-access-server/internal/audit"
	"github.com/freifunkMUC/wg-access-server/internal/authnz"
	"github.com/freifunkMUC/wg-access-server/internal/authnz/authsession"
	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/metrics"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-access-server/internal/web"
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

// newRouter builds the web server: the endpoints anyone may reach, and
// behind the authentication middleware the API and the web UI.
// recordLogin remembers somebody who signed in. A failure is logged and no
// more: the sign-in itself worked, and refusing it because of a write that is
// only needed later would be the worse outcome.
func recordLogin(storageBackend storage.Storage) func(*authsession.Identity) {
	return func(identity *authsession.Identity) {
		user := &storage.User{
			Subject:   identity.Subject,
			Provider:  identity.Provider,
			Name:      identity.Name,
			Email:     identity.Email,
			LastLogin: time.Now(),
		}
		if err := storageBackend.SaveUser(user); err != nil {
			logrus.Error(fmt.Errorf("failed to remember the user that signed in: %w", err))
		}
	}
}

func newRouter(conf *config.AppConfig, deviceManager *devices.DeviceManager, storageBackend storage.Storage, wg wgembed.WireGuardInterface) (http.Handler, error) {
	router := mux.NewRouter()
	router.Use(web.TracesMiddleware)
	router.Use(web.RecoveryMiddleware)
	router.Use(web.SecurityHeadersMiddleware)
	router.Use(audit.Middleware)
	// Refuses a POST (or PUT, DELETE, ...) a browser sends on behalf of
	// another site: signing in or out, and the API. Scripts send no such
	// headers and are not affected.
	router.Use(http.NewCrossOriginProtection().Handler)

	// Health check endpoint
	router.PathPrefix("/health").Handler(web.HealthEndpoint(deviceManager))

	// Prometheus metrics endpoint (optionally basic-auth protected)
	router.Path("/metrics").Handler(metrics.Endpoint(&metrics.Deps{
		DeviceManager: deviceManager,
		Metadata:      conf.EnableMetadata,
		DeviceMetrics: conf.EnableDeviceMetrics,
		Metrics:       conf.Metrics,
	}))

	// Authentication middleware
	claims := authnz.ClaimsMiddleware(conf)
	middleware, err := authnz.NewMiddleware(conf.Auth, claims, authnz.WithLoginRecorder(recordLogin(storageBackend)))
	if err != nil {
		return nil, fmt.Errorf("failed to set up authnz middleware: %w", err)
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
	site.PathPrefix("/").Handler(web.Router())

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
				errChan <- fmt.Errorf("unable to start http server: %w", err)
			}
		}()
	}

	var httpsSrv *http.Server
	if conf.HTTPS.Enabled {
		httpsAddress := fmt.Sprintf("%s:%d", conf.HTTPS.Host, conf.HTTPS.Port)

		certPath := conf.HTTPS.CertFile
		keyPath := conf.HTTPS.KeyFile
		if certPath == "" || keyPath == "" {
			certPath, keyPath = web.GetDefaultCertPaths()
		}

		tlsConfig, err := web.LoadTLSCert(certPath, keyPath, web.CertHosts(conf.ExternalHost))
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
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
				errChan <- fmt.Errorf("unable to start https server: %w", err)
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
				logrus.Error(fmt.Errorf("unable to shutdown http server: %w", err))
			}
		}
		if httpsSrv != nil {
			if err := httpsSrv.Shutdown(ctx); err != nil {
				logrus.Error(fmt.Errorf("unable to shutdown https server: %w", err))
			}
		}
		return nil
	case err := <-errChan:
		return err
	}
}
