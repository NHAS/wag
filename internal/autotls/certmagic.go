package autotls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/tetcd/watch"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

type webserver struct {
	listener *http.Server
	mux      http.Handler
	details  *config.WebserverDetails
}

type AutoTLS struct {
	*certmagic.Config

	sync.RWMutex

	rollbackCount atomic.Int32
	webServers    map[data.Webserver]*webserver

	issuer *certmagic.ACMEIssuer

	db interfaces.Database

	http01Challenge *http.Server
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

	certmagic.Default.Storage = data.NewCertStore(db.Raw(), "wag-certificates")

	config := certmagic.NewDefault()
	// apparently it is important to set the storage before creating a config
	config.Storage = certmagic.Default.Storage

	issuer := certmagic.NewACMEIssuer(config, certmagic.ACMEIssuer{
		CA:                      provider,
		Email:                   email,
		Agreed:                  true,
		DisableTLSALPNChallenge: true,
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
		Config:     config,
		webServers: make(map[data.Webserver]*webserver),
		issuer:     issuer,
		db:         db,
	}

	if Do != nil {
		panic("should not occur")
	}

	err = ret.startAutoRedirector()
	if err != nil {
		log.Warn().Err(err).Msg("could not start port 80 redirector, this will break HTTP-01 TLS transactions")
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

	if a.http01Challenge != nil {
		if _, port, err := net.SplitHostPort(initialDetails.ListenAddress); err == nil && port == "80" {
			log.Info().Err(err).Str("webserver", string(forWhat)).Msg("Shutdown default 80/tcp http listener as webserver is listening on 80/tcp")

			a.http01Challenge.Close()
			a.http01Challenge = nil
		}
	}

	if err := a.refreshListeners(forWhat, mux, &initialDetails); err != nil {
		a.db.RaiseError(err, []byte(""))
		log.Info().Err(err).Str("webserver", string(forWhat)).Msg("could not start web server")
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

	if w.listener != nil {
		w.listener.Close()
	}

	w.listener = nil
}

// HalfClose shuts down all active server listeners, but does not clear the web server config or mux routes
func (a *AutoTLS) HalfClose(what data.Webserver) {
	a.Lock()
	defer a.Unlock()
	a.halfClose(what)
}

func (a *AutoTLS) registerEventListeners() error {
	ctx := context.Background()

	err := data.Config.Webserver.Acme.CloudflareDNSToken().Watch(ctx, a.db.Raw()).Start(
		watch.All(func(ctx context.Context, event watch.Event[config.CloudflareToken]) error {
			a.Lock()
			defer a.Unlock()

			if event.Type == watch.DELETED || event.Current.APIToken == "" {
				a.issuer.DNS01Solver = nil
			} else {
				a.issuer.DNS01Solver = &certmagic.DNS01Solver{
					DNSManager: certmagic.DNSManager{
						DNSProvider: &cloudflare.Provider{
							APIToken: event.Current.APIToken,
						},
					},
				}
			}

			return nil
		}))
	if err != nil {
		return err
	}

	err = data.Config.Webserver.Acme.Email().Watch(ctx, a.db.Raw()).Start(
		watch.All(func(ctx context.Context, event watch.Event[string]) error {
			a.Lock()
			defer a.Unlock()

			a.issuer.Email = event.Current
			if event.Type == watch.DELETED {
				a.issuer.Email = ""
			}

			return nil
		}))
	if err != nil {
		return err
	}

	err = data.Config.Webserver.Acme.CAProvider().Watch(ctx, a.db.Raw()).Start(
		watch.All(func(ctx context.Context, event watch.Event[string]) error {
			a.Lock()
			defer a.Unlock()

			a.issuer.CA = event.Current
			if event.Type == watch.DELETED {
				a.issuer.CA = ""
			}

			return nil
		}))
	if err != nil {
		return err
	}

	webserverEventsFunc :=
		func(webserver data.Webserver) watch.CallbackFunc[config.WebserverDetails] {
			return func(ctx context.Context, event watch.Event[config.WebserverDetails]) error {

				a.RLock()
				// we dont update the webserver config here, it is done in the refreshListners call as the operation is mildly complicated
				_, ok := a.webServers[webserver]
				a.RUnlock()

				// if the web server has been entirely closed, or deleted then we cant re-open it automatically
				if !ok {
					return nil
				}

				if event.Type == watch.DELETED {
					// shouldnt happen, but may as well handle it
					a.HalfClose(webserver)
					return nil
				}
				// nil means we keep the established mux
				preserveError := a.refreshListeners(webserver, nil, &event.Current)
				if preserveError != nil {
					a.rollbackCount.Add(1)

					if a.rollbackCount.Load() < 2 {
						a.db.SetWebserverConfig(webserver, event.Previous)
						a.db.RaiseError(fmt.Errorf("could not change webserver %q, an error occurred %s, rolling back", webserver, preserveError), []byte(""))
					} else {
						a.db.RaiseError(fmt.Errorf("could not rollback %q changes to working configuration", webserver), []byte(""))
					}
					return preserveError
				}

				a.startAutoRedirector()

				a.rollbackCount.Store(0)

				return nil
			}
		}

	err = data.Config.Webserver.Tunnel.HTTPSettings.Watch(ctx, a.db.Raw()).Start(watch.All(webserverEventsFunc(data.Tunnel)))
	if err != nil {
		return err
	}

	err = data.Config.Webserver.Public.HTTPSettings.Watch(ctx, a.db.Raw()).Start(watch.All(webserverEventsFunc(data.Public)))
	if err != nil {
		return err
	}

	err = data.Config.Webserver.Management.HTTPSettings.Watch(ctx, a.db.Raw()).Start(watch.All(webserverEventsFunc(data.Management)))
	if err != nil {
		return err
	}

	return err
}

func (a *AutoTLS) refreshListeners(forWhat data.Webserver, mux http.Handler, details *config.WebserverDetails) error {
	ctx := context.Background()

	a.Lock()
	defer a.Unlock()

	w, ok := a.webServers[forWhat]
	if !ok {
		if mux == nil || details == nil {
			return fmt.Errorf("refreshing webserver %q config failed, server not currently on", forWhat)
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

	if w.listener != nil {
		w.listener.Close()
	}

	w.listener = &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       5 * time.Minute,
		Handler:           w.mux,
		BaseContext:       func(listener net.Listener) context.Context { return ctx },
	}

	// TODO the below code is quite repetitious, we should seperate these out into functions to reduce duplication. Future me, away!
	// if we have no domain, or tls is explicitly disabled ( or acme provider hasnt been configured )
	// open an http only port on whatever the listen address is
	if w.details.Domain == "" || !w.details.TLS {

		if len(a.Issuers) > 0 {
			// just start an http-01 handler on anything thats not tls
			if am, ok := a.Issuers[0].(*certmagic.ACMEIssuer); ok {
				w.listener.Handler = am.HTTPChallengeHandler(w.mux)
			}
		}

		httpListener, err := net.Listen("tcp", w.details.ListenAddress)
		if err != nil {
			return err
		}

		go w.listener.Serve(httpListener)
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

			httpsLn, err := tls.Listen("tcp", w.details.ListenAddress, tlsConfig)
			if err != nil {
				return err
			}
			go w.listener.Serve(httpsLn)

		} else {
			// if TLS is enabled but we are using ACME to auto provision certs
			if len(a.Issuers) == 0 {
				return fmt.Errorf("no issuers were setup for ACME TLS provider")
			}

			// attempt to start the listener just in case
			a.startAutoRedirector()

			err := a.Config.ManageSync(ctx, []string{w.details.Domain})
			if err != nil {
				return err
			}

			tlsConfig := a.Config.TLSConfig()
			tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

			httpsLn, err := tls.Listen("tcp", w.details.ListenAddress, tlsConfig)
			if err != nil {
				return err
			}
			go w.listener.Serve(httpsLn)

		}
	}

	return nil
}

func (a *AutoTLS) startAutoRedirector() error {
	// this is only to be used within the critical section
	ctx := context.Background()

	if a.http01Challenge != nil {
		a.http01Challenge.Close()
	}

	httpRedirectListener, err := net.Listen("tcp", ":80")
	if err != nil {
		return err
	}

	log.Info().Msg("Started http redirector on port 80")

	a.http01Challenge = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		BaseContext:       func(listener net.Listener) context.Context { return ctx },
	}

	if am, ok := a.Issuers[0].(*certmagic.ACMEIssuer); ok && a.issuer.DNS01Solver == nil {
		a.http01Challenge.Handler = am.HTTPChallengeHandler(http.HandlerFunc(a.httpRedirectHandler()))
	}

	go a.http01Challenge.Serve(httpRedirectListener)
	return nil
}

func (a *AutoTLS) httpRedirectHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get rid of this disgusting unencrypted HTTP connection 🤢

		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "https://"+r.Host, http.StatusMovedPermanently)
	}
}
