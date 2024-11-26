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
	"time"

	"github.com/NHAS/wag/internal/data"
	"github.com/caddyserver/certmagic"
)

type webserver struct {
	listeners []*http.Server
	mux       http.Handler
	close     chan interface{}
	isClosed  bool
	details   data.WebserverConfiguration
}

type AutoTLS struct {
	*certmagic.Config

	sync.RWMutex

	webServers map[data.Webserver]*webserver

	issuer *certmagic.ACMEIssuer
}

var Do *AutoTLS

func Initialise() error {

	email, err := data.GetAcmeEmail()
	if err != nil {
		email = ""
	}

	// Defaults to lets encrypt production if nothing is set
	provider, err := data.GetAcmeProvider()
	if err != nil {
		provider = ""
	}

	config := certmagic.NewDefault()
	config.Storage = data.NewCertStore("wag-certificates")

	issuer := certmagic.NewACMEIssuer(&certmagic.Default, certmagic.ACMEIssuer{
		CA:     provider,
		Email:  email,
		Agreed: true,
	})

	if provider != "" && email != "" {
		config.Issuers = []certmagic.Issuer{issuer}
	}

	ret := &AutoTLS{
		Config:     config,
		webServers: make(map[data.Webserver]*webserver),
		issuer:     issuer}
	ret.registerEventListeners()

	if Do != nil {
		panic("should not occur")
	}

	Do = ret
	return nil
}

func (a *AutoTLS) DynamicListener(forWhat data.Webserver, mux http.Handler) error {

	if mux == nil {
		panic("no handler provided")
	}

	initialDetails, err := data.GetWebserverConfig(forWhat)
	if err != nil {
		return err
	}

	return a.refreshListeners(forWhat, mux, initialDetails)
}

func (a *AutoTLS) Close(what data.Webserver) {
	a.Lock()
	defer a.Unlock()
	w, ok := a.webServers[what]
	if !ok {
		return
	}

	for _, s := range w.listeners {
		s.Close()
	}

	w.isClosed = true

	delete(a.webServers, what)

	close(w.close)
}

func (a *AutoTLS) registerEventListeners() error {

	_, err := data.RegisterEventListener(data.AcmeEmailKey, false, func(_, current, previous string, ev data.EventType) error {

		a.issuer.Email = current
		if ev == data.DELETED {
			a.issuer.Email = ""
		}

		if a.issuer.CA == "" || a.issuer.Email == "" {
			a.Config.Issuers = []certmagic.Issuer{}
		} else {
			a.Config.Issuers = []certmagic.Issuer{a.issuer}
		}

		// todo refesh with stored details & mux

		return nil
	})
	if err != nil {
		return err
	}

	_, err = data.RegisterEventListener(data.AcmeProviderKey, false, func(_, current, previous string, ev data.EventType) error {

		a.issuer.CA = current
		if ev == data.DELETED {
			a.issuer.CA = ""
		}

		if a.issuer.CA == "" || a.issuer.Email == "" {
			a.Config.Issuers = []certmagic.Issuer{}
		} else {
			a.Config.Issuers = []certmagic.Issuer{a.issuer}
		}

		// todo refesh with stored details & mux

		return nil
	})
	if err != nil {
		return err
	}

	webserverEventsFunc := func(key string, current, _ data.WebserverConfiguration, ev data.EventType) error {

		webserverTarget := data.Webserver(strings.TrimPrefix(key, data.WebServerConfigKey))
		a.RLock()
		_, ok := a.webServers[webserverTarget]
		a.RUnlock()

		if !ok {
			return nil
		}

		if ev == data.DELETED {
			a.Close(webserverTarget)
			return nil
		}

		// todo reopen after close, thus rethink about how close fully works

		// nil means we keep the established mux
		return a.refreshListeners(webserverTarget, nil, current)
	}

	_, err = data.RegisterEventListener(data.TunnelWebServerConfigKey, false, webserverEventsFunc)
	if err != nil {
		return err
	}

	_, err = data.RegisterEventListener(data.PublicWebServerConfigKey, false, webserverEventsFunc)
	if err != nil {
		return err
	}

	_, err = data.RegisterEventListener(data.ManagementWebServerConfigKey, false, webserverEventsFunc)
	if err != nil {
		return err
	}

	return nil
}

func (a *AutoTLS) refreshListeners(forWhat data.Webserver, mux http.Handler, details data.WebserverConfiguration) error {
	ctx := context.Background()

	a.Lock()
	defer a.Unlock()

	w, ok := a.webServers[forWhat]
	if !ok {
		if mux == nil {
			return errors.New("refresh called from events while web server doesnt exist")
		}
		w = &webserver{
			mux:      mux,
			isClosed: false,
			close:    make(chan interface{}),
		}
		a.webServers[forWhat] = w
	}
	w.details = details

	if w.details.Domain == "" || !w.details.TLS || len(a.Issuers) == 0 {
		httpListener, err := net.Listen("tcp", w.details.ListenAddress)
		if err != nil {
			return err
		}

		httpServer := &http.Server{
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
		w.listeners = []*http.Server{httpServer}

		go httpServer.Serve(httpListener)
	} else {
		err := a.Config.ManageSync(ctx, []string{w.details.Domain})
		if err != nil {
			return err
		}

		tlsConfig := a.Config.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

		httpsLn, err := tls.Listen("tcp", fmt.Sprintf(w.details.ListenAddress), tlsConfig)
		if err != nil {
			return err
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
		if err != nil {
			log.Println("WARNING could start acme tls listener on", w.details.ListenAddress, err, " auto provisioning certificate may fail")
		} else {
			w.listeners = append(w.listeners, httpRedirectServer)
		}

		w.listeners = append(w.listeners, httpsServer)

		go httpsServer.Serve(httpsLn)

	}

	return nil
}

func (a *AutoTLS) autoRedirector(httpsServerListenAddr, domain string) (*http.Server, error) {
	ctx := context.Background()

	host, port, err := net.SplitHostPort(httpsServerListenAddr)
	if err != nil {
		host = httpsServerListenAddr
		port = "443"
	}

	httpRedirectListener, err := net.Listen("tcp", fmt.Sprintf("%s:80", host))
	if err != nil {
		return nil, err
	}

	httpServer := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		BaseContext:       func(listener net.Listener) context.Context { return ctx },
	}

	if am, ok := a.Issuers[0].(*certmagic.ACMEIssuer); ok {
		// todo dns-01
		httpServer.Handler = am.HTTPChallengeHandler(http.HandlerFunc(a.httpRedirectHandler(domain + ":" + port)))
	}

	go httpServer.Serve(httpRedirectListener)

	return httpServer, nil
}

func (a *AutoTLS) httpRedirectHandler(redirectTo string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// get rid of this disgusting unencrypted HTTP connection 🤢
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, "https://"+redirectTo, http.StatusMovedPermanently)
	}
}
