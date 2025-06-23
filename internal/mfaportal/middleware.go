package mfaportal

import (
	"context"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
)

type userChecks struct {
	next http.Handler
	f    *router.Firewall
	db   interfaces.Database
}

func (d *userChecks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	userObj, err := users.GetUserFromAddress(d.db, clientTunnelIp)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		log.Printf("device with unknown ip %q (%q, xff %q, NumberOfProxies: %d) used vpn endpoint CHECK CONFIG", clientTunnelIp, r.Host, r.Header.Get("X-forwarded-for"), config.Values.NumberProxies)
		return
	}

	ctx := context.WithValue(r.Context(), users.UserContextKey, &userObj)

	if clientTunnelIp != nil {
		ctx = context.WithValue(ctx, authContext, d.f.IsAuthed(clientTunnelIp.String()))
	}
	// Create new request with updated context
	r = r.WithContext(ctx)

	d.next.ServeHTTP(w, r)
}

func fetchState(f http.Handler, db interfaces.Database, firewall *router.Firewall) http.Handler {
	return &userChecks{
		next: f,
		f:    firewall,
		db:   db,
	}
}

type authContextKey string

// Define context key for user
const authContext authContextKey = "authed"

func Authed(ctx context.Context) bool {
	authed, ok := ctx.Value(authContext).(bool)
	return ok && authed
}
