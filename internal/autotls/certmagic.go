package autotls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/data/watcher"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

type webserver struct {
	listeners []*http.Server
	mux       http.Handler
	details   *data.WebserverConfiguration
}

type AutoTLS struct {
	*certmagic.Config

	sync.RWMutex

	rollbackCount atomic.Int32
	webServers    map[data.Webserver]*webserver

	ourHttpServers map[string]bool

	issuer *certmagic.ACMEIssuer

	db interfaces.Database
}

var Do *AutoTLS

func Initialise(db interfaces.Database) error {

	email, err := db.GetAcmeEmail()
	if err != nil {
		email = ""
	}

	// Defaults to lets encrypt production if nothing is set
	provider, err := db.GetAcmeProvider()
	if err != nil {
		provider = ""
	}

	cfDnsToken, err := db.GetAcmeDNS01CloudflareToken()
	if err != nil {
		cfDnsToken.APIToken = ""
	}

	config := certmagic.NewDefault()
	config.Storage = data.NewCertStore(db.Raw(), "wag-certificates")

	issuer := certmagic.NewACMEIssuer(config, certmagic.ACMEIssuer{
		CA:     provider,
		Email:  email,
		Agreed: true,
	})

	if cfDnsToken.APIToken != "" {
		// enabling the dns challenge disables all other methods
		issuer.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflare.Provider{
					APIToken: cfDnsToken.APIToken,
				},
			},
		}
	}

	config.Issuers = []certmagic.Issuer{issuer}

	ret := &AutoTLS{
		Config:         config,
		webServers:     make(map[data.Webserver]*webserver),
		issuer:         issuer,
		ourHttpServers: make(map[string]bool),
		db:             db,
	}

	if Do != nil {
		panic("should not occur")
	}

	err = ret.registerEventListeners()
	if err != nil {
		return fmt.Errorf("failed to register events for auto tls: %w", err)
	}

	Do = ret
	return nil
}

func (a *AutoTLS) DynamicListener(forWhat data.Webserver, mux http.Handler) error {

	if mux == nil {
		panic("no handler provided")
	}

	initialDetails, err := a.db.GetWebserverConfig(forWhat)
	if err != nil {
		return fmt.Errorf("could not get initial web server config for %s: %w", forWhat, err)
	}

	if err := a.refreshListeners(forWhat, mux, &initialDetails); err != nil {
		a.db.RaiseError(err, []byte(""))
		log.Printf("could not start web server for %q, err: %s", forWhat, err)
	}

	return nil
}

// The server is entirely closed, must be reopened with "DynamicListener"
func (a *AutoTLS) Close(what data.Webserver) {
	a.Lock()
	defer a.Unlock()

	a.halfClose(what)

	delete(a.webServers, what)
}

func (a *AutoTLS) halfClose(what data.Webserver) {
	w, ok := a.webServers[what]
	if !ok {
		return
	}

	for _, s := range w.listeners {
		s.Close()
	}

	w.listeners = []*http.Server{}
}

// HalfClose shuts down all active server listeners, but does not clear the web server config or mux routes
func (a *AutoTLS) HalfClose(what data.Webserver) {
	a.Lock()
	defer a.Unlock()
	a.halfClose(what)
}

func (a *AutoTLS) registerEventListeners() error {

	_, err := watcher.WatchAll(a.db, data.AcmeDNS01CloudflareAPIToken, false, func(_ string, ev data.EventType, current, previous data.CloudflareToken) error {
		if ev == data.DELETED || current.APIToken == "" {
			a.issuer.DNS01Solver = nil
		} else {
			a.issuer.DNS01Solver = &certmagic.DNS01Solver{
				DNSManager: certmagic.DNSManager{
					DNSProvider: &cloudflare.Provider{
						APIToken: current.APIToken,
					},
				},
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	_, err = watcher.WatchAll(a.db, data.AcmeEmailKey, false, func(_ string, ev data.EventType, current, previous string) error {

		a.issuer.Email = current
		if ev == data.DELETED {
			a.issuer.Email = ""
		}

		return nil
	})
	if err != nil {
		return err
	}

	_, err = watcher.WatchAll(a.db, data.AcmeProviderKey, false, func(_ string, ev data.EventType, current, previous string) error {

		a.issuer.CA = current
		if ev == data.DELETED {
			a.issuer.CA = ""
		}

		return nil
	})
	if err != nil {
		return err
	}

	webserverEventsFunc := func(key string, ev data.EventType, current, previous data.WebserverConfiguration) error {

		webserverTarget := data.Webserver(strings.TrimPrefix(key, data.WebServerConfigKey))
		a.RLock()
		// we dont update the webserver config here, it is done in the refreshListners call as the operation is mildly complicated
		_, ok := a.webServers[webserverTarget]
		a.RUnlock()

		// if the web server has been entirely closed, or deleted then we cant re-open it automatically
		if !ok {
			return nil
		}

		if ev == data.DELETED {
			// shouldnt happen, but may as well handle it
			a.HalfClose(webserverTarget)
			return nil
		}
		// nil means we keep the established mux
		preserveError := a.refreshListeners(webserverTarget, nil, &current)
		if preserveError != nil {
			a.rollbackCount.Add(1)

			if a.rollbackCount.Load() < 2 {
				a.db.SetWebserverConfig(webserverTarget, previous)
				a.db.RaiseError(fmt.Errorf("could not change webserver %q, an error occured %s, rolling back", webserverTarget, preserveError), []byte(""))
			} else {
				a.db.RaiseError(fmt.Errorf("could not rollback %q changes to working configuration", webserverTarget), []byte(""))
			}
			return preserveError
		}

		a.rollbackCount.Store(0)

		return nil
	}

	// this is event closed so we can discard access to the watcher
	_, err = watcher.WatchMulti(a.db, []string{
		data.TunnelWebServerConfigKey,
		data.PublicWebServerConfigKey,
		data.ManagementWebServerConfigKey,
	}, false,
		watcher.WatcherCallbacks[data.WebserverConfiguration]{
			All: webserverEventsFunc,
		})

	return err
}

func (a *AutoTLS) refreshListeners(forWhat data.Webserver, mux http.Handler, details *data.WebserverConfiguration) error {
	ctx := context.Background()

	a.Lock()
	defer a.Unlock()

	w, ok := a.webServers[forWhat]
	if !ok {
		if mux == nil || details == nil {
			return errors.New("refreshing webserver " + string(forWhat) + " config failed, server not currently on")
		}

		w = &webserver{
			mux:     mux,
			details: details,
		}
		a.webServers[forWhat] = w
	}

	if details != nil {
		w.details = details
	}

	// TODO the below code is quite repetitious, we should seperate these out into functions to reduce duplication. Future me, away!
	// if we have no domain, or tls is explicitly disabled ( or acme provider hasnt been configured )
	// open an http only port on whatever the listen address is
	if w.details.Domain == "" || !w.details.TLS {

		httpServer := &http.Server{
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      2 * time.Minute,
			IdleTimeout:       5 * time.Minute,
			Handler:           w.mux,
			BaseContext:       func(listener net.Listener) context.Context { return ctx },
		}

		if len(a.Issuers) > 0 {
			if am, ok := a.Issuers[0].(*certmagic.ACMEIssuer); ok {
				httpServer.Handler = am.HTTPChallengeHandler(w.mux)
			}
		}
		for _, s := range w.listeners {
			s.Close()
		}
		w.listeners = []*http.Server{httpServer}

		httpListener, err := net.Listen("tcp", w.details.ListenAddress)
		if err != nil {
			return err
		}

		go a.runHttpServer(httpServer, httpListener)
	} else if w.details.TLS {

		if w.details.StaticCerts {
			cert, err := tls.X509KeyPair([]byte(w.details.CertificatePEM), []byte(w.details.PrivateKeyPEM))
			if err != nil {
				return fmt.Errorf("x509 keypair was bad, either custom certificate or custom key was bad: %w", err)
			}

			// this is effectively just copied from cert magic
			tlsConfig := &tls.Config{
				GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return &cert, nil
				},

				// the rest recommended for modern TLS servers
				MinVersion: tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.X25519,
					tls.CurveP256,
				},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
				PreferServerCipherSuites: true,
			}

			httpsServer := &http.Server{
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      2 * time.Minute,
				IdleTimeout:       5 * time.Minute,
				Handler:           w.mux,
				BaseContext:       func(listener net.Listener) context.Context { return ctx },
			}
			for _, s := range w.listeners {
				s.Close()
			}
			w.listeners = []*http.Server{}

			httpRedirectServer, err := a.autoRedirector(w.details.ListenAddress, w.details.Domain)
			if err == nil {
				w.listeners = append(w.listeners, httpRedirectServer)
			}

			w.listeners = append(w.listeners, httpsServer)

			httpsLn, err := tls.Listen("tcp", w.details.ListenAddress, tlsConfig)
			if err != nil {
				return err
			}
			go httpsServer.Serve(httpsLn)

		} else {

			if len(a.Issuers) == 0 {
				return fmt.Errorf("no issuers were setup for ACME TLS provider")
			}
			err := a.Config.ManageSync(ctx, []string{w.details.Domain})
			if err != nil {
				return err
			}

			tlsConfig := a.Config.TLSConfig()
			tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

			httpsServer := &http.Server{
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      2 * time.Minute,
				IdleTimeout:       5 * time.Minute,
				Handler:           w.mux,
				BaseContext:       func(listener net.Listener) context.Context { return ctx },
			}
			for _, s := range w.listeners {
				s.Close()
			}
			w.listeners = []*http.Server{}

			httpRedirectServer, err := a.autoRedirector(w.details.ListenAddress, w.details.Domain)
			if err == nil {
				w.listeners = append(w.listeners, httpRedirectServer)
			}

			w.listeners = append(w.listeners, httpsServer)

			httpsLn, err := tls.Listen("tcp", w.details.ListenAddress, tlsConfig)
			if err != nil {
				return err
			}
			go httpsServer.Serve(httpsLn)

		}
	}

	return nil
}

func (a *AutoTLS) autoRedirector(httpsServerListenAddr, domain string) (*http.Server, error) {
	// this is only to be used within the critical section
	ctx := context.Background()

	host, port, err := net.SplitHostPort(httpsServerListenAddr)
	if err != nil {
		host = httpsServerListenAddr
		port = "443"
	}

	listenAddr := fmt.Sprintf("%s:80", host)

	if a.ourHttpServers[listenAddr] || a.ourHttpServers[":80"] {
		return nil, errors.New("ignore me, we already have an http listener on this port")
	}

	httpRedirectListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}

	a.ourHttpServers[listenAddr] = true

	httpServer := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		BaseContext:       func(listener net.Listener) context.Context { return ctx },
	}

	if am, ok := a.Issuers[0].(*certmagic.ACMEIssuer); ok {
		httpServer.Handler = am.HTTPChallengeHandler(http.HandlerFunc(a.httpRedirectHandler(domain + ":" + port)))
	}

	go a.runHttpServer(httpServer, httpRedirectListener)
	return httpServer, nil
}

func (a *AutoTLS) httpRedirectHandler(redirectTo string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get rid of this disgusting unencrypted HTTP connection 🤢
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "https://"+redirectTo, http.StatusMovedPermanently)
	}
}

func (a *AutoTLS) runHttpServer(httpServer *http.Server, listener net.Listener) {
	httpServer.Serve(listener)
	a.Lock()
	delete(a.ourHttpServers, listener.Addr().String())
	a.Unlock()
}
