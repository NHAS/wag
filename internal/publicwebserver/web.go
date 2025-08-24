package publicwebserver

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/NHAS/wag/internal/autotls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/NHAS/wag/internal/publicwebserver/resources"

	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PublicWebserver struct {
	firewall *router.Firewall
	db       interfaces.Database
}

func (es *PublicWebserver) Close() {
	autotls.Do.Close(data.Public)
}

func (es *PublicWebserver) registerDevice(w http.ResponseWriter, r *http.Request) {
	remoteAddr := utils.GetIPFromRequest(r)

	key, err := url.PathUnescape(r.URL.Query().Get("key"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if len(key) == 0 {
		log.Println("unknown", remoteAddr, "no registration key specified, ignoring")
		http.NotFound(w, r)
		return
	}

	username, overwrites, staticIp, groups, tag, err := es.db.GetRegistrationToken(key)
	if err != nil {
		log.Println(username, remoteAddr, "failed to get registration key:", err)
		http.NotFound(w, r)
		return
	}

	var publickey, privatekey wgtypes.Key
	pubkeyParam, err := url.PathUnescape(r.URL.Query().Get("pubkey"))
	if err != nil {
		log.Println(username, remoteAddr, "failed to url decode public key paramter:", err)
		http.NotFound(w, r)
		return
	}

	if len(pubkeyParam) != 0 {
		publickey, err = wgtypes.ParseKey(pubkeyParam)
		if err != nil {
			log.Println(username, remoteAddr, "failed to unmarshal wireguard public key:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	} else {
		privatekey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Println(username, remoteAddr, "failed to generate wireguard keys:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		publickey = privatekey.PublicKey()
	}

	user, err := users.GetUser(es.db, username)
	if err != nil {
		user, err = users.CreateUser(es.db, username)
		if err != nil {
			log.Println(username, remoteAddr, "unable create new user: "+err.Error())
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	if len(groups) != 0 {
		err := es.db.SetUserGroupMembership(username, groups, false)
		if err != nil {
			log.Println(username, remoteAddr, "could not set user membership from registration token:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	}

	var (
		address string
	)
	if overwrites != "" {

		err = user.SetDevicePublicKey(publickey.String(), overwrites)
		if err != nil {
			log.Printf("%s %s couldnt update %q: %s", username, remoteAddr, overwrites, err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		address = overwrites

	} else {

		// Make sure not to accidentally shadow the global err here as we're using a defer to monitor failures to delete the device
		var device data.Device
		device, err = user.AddDevice(publickey, staticIp, tag)
		if err != nil {
			log.Println(username, remoteAddr, "unable to add device: ", err)

			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
		address = device.Address

		defer func() {

			if err != nil {
				log.Println(username, remoteAddr, "removing device (due to registration failure)")
				err := user.DeleteDevice(device.Address)
				if err != nil {
					log.Println(username, remoteAddr, "unable to remove wg device: ", err)
				}
			}
		}()
	}

	acl := es.db.GetEffectiveAcl(username)

	wgPublicKey, wgPort, err := es.firewall.ServerDetails()
	if err != nil {
		log.Println(username, remoteAddr, "unable access wireguard device: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	keyStr := privatekey.String()
	//Empty value of a private key in wgtype.Key
	if keyStr == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		keyStr = ""
	}

	presharedKey, err := user.GetDevicePresharedKey(address)
	if err != nil {
		log.Println(username, remoteAddr, "unable access device preshared key: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	dnsWithOutSubnet, err := es.db.GetDNS()
	if err != nil {
		log.Println(username, remoteAddr, "unable get dns: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	for i := 0; i < len(dnsWithOutSubnet); i++ {
		dnsWithOutSubnet[i] = strings.TrimSuffix(strings.TrimSuffix(dnsWithOutSubnet[i], "/32"), "/128")
	}

	routes, err := routetypes.AclsToRoutes(append(acl.Allow, acl.Mfa...))
	if err != nil {
		log.Println(username, remoteAddr, "unable access parse acls to produce routes: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	wireguardInterface := resources.WireguardConfig{
		ClientPrivateKey:   keyStr,
		ClientAddress:      address,
		ServerPublicKey:    wgPublicKey.String(),
		CapturedAddresses:  routes,
		DNS:                dnsWithOutSubnet,
		ClientPresharedKey: presharedKey,
	}

	externalAddress, err := es.db.GetExternalAddress()
	if err != nil {
		log.Println(username, remoteAddr, "unable to get server external address from datastore: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// If the external address defined in the config has a port, use that, otherwise defaultly add the same port as the wireguard device
	_, _, err = net.SplitHostPort(externalAddress)
	if err != nil {
		externalAddress = fmt.Sprintf("%s:%d", externalAddress, wgPort)
	}

	wireguardInterface.ServerAddress = externalAddress

	w.Header().Set("Content-Disposition", "attachment; filename="+es.db.GetWireguardConfigName())

	err = resources.RenderWithFuncs("wgconf_enrolment.tmpl", w, &wireguardInterface, template.FuncMap{
		"StringsJoin": strings.Join,
		"Unescape":    func(s string) template.HTML { return template.HTML(s) },
	})
	if err != nil {
		log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	//Finish registration process
	err = es.db.FinaliseRegistration(key)
	if err != nil {
		log.Println(username, remoteAddr, "expiring registration token failed:", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	logMsg := "registered as"
	if overwrites != "" {
		logMsg = "overwrote"
	}
	log.Println(username, remoteAddr, "successfully", logMsg, address, ":", publickey.String())
}

func (es *PublicWebserver) reachability(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "text/plain")

	isDrained, err := es.db.IsClusterNodeDrained(es.db.GetCurrentNodeID().String())
	if err != nil {
		http.Error(w, "Failed to fetch state", http.StatusInternalServerError)
		return
	}

	if !isDrained {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	w.WriteHeader(http.StatusGone)
	w.Write([]byte("Drained"))

}

func (es *PublicWebserver) webhooks(w http.ResponseWriter, r *http.Request) {

	parts := strings.SplitN(r.URL.Path, "/", 3)
	if len(parts) != 3 {
		http.NotFound(w, r)
		return
	}

	authHeader := r.Header.Get("X-AUTH-HEADER")

	id := parts[len(parts)-1]

	if !es.db.CheckWebhookAuth(id, authHeader) {
		http.NotFound(w, r)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4097)

	buffer := bytes.NewBuffer(nil)
	_, err := io.Copy(buffer, r.Body)
	if err != nil {
		log.Println("failed to read webhook request: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	err = es.db.WebhookRecordLastRequest(id, authHeader, buffer.String())
	if err != nil {
		log.Println("failed to update webhook last request: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func New(db interfaces.Database, firewall *router.Firewall, errChan chan<- error) (*PublicWebserver, error) {
	if firewall == nil {
		panic("firewall was nil")
	}

	es := PublicWebserver{
		firewall: firewall,
		db:       db,
	}

	public := http.NewServeMux()
	public.HandleFunc("GET /reachability", es.reachability)
	public.HandleFunc("GET /register_device", es.registerDevice)
	public.HandleFunc("/webhooks/", es.webhooks)

	if err := autotls.Do.DynamicListener(data.Public, public); err != nil {
		return nil, err
	}

	log.Println("[ENROLMENT] Public enrolment listening: ", config.Values.Webserver.Public.ListenAddress)

	return &es, nil

}
