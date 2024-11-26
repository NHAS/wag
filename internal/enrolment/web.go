package enrolment

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"image/png"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/NHAS/wag/internal/autotls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/enrolment/resources"
	styling "github.com/NHAS/wag/internal/mfaportal/resources"

	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type EnrolmentServer struct {
	firewall *router.Firewall
}

func (es *EnrolmentServer) Close() {
	autotls.Do.Close(data.Public)
}

func (es *EnrolmentServer) registerDevice(w http.ResponseWriter, r *http.Request) {
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

	username, overwrites, groups, err := data.GetRegistrationToken(key)
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

	user, err := users.GetUser(username)
	if err != nil {
		user, err = users.CreateUser(username)
		if err != nil {
			log.Println(username, remoteAddr, "unable create new user: "+err.Error())
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	if len(groups) != 0 {
		err := data.SetUserGroupMembership(username, groups)
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
		device, err = user.AddDevice(publickey)
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

	acl := data.GetEffectiveAcl(username)

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

	dnsWithOutSubnet, err := data.GetDNS()
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

	externalAddress, err := data.GetExternalAddress()
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

	if r.URL.Query().Get("type") == "mobile" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")

		var wireguardProfile bytes.Buffer
		err = resources.RenderWithFuncs("interface.tmpl", &wireguardProfile, &wireguardInterface, template.FuncMap{
			"StringsJoin": strings.Join,
			"Unescape":    func(s string) template.HTML { return template.HTML(s) },
		})
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		image, err := qr.Encode(wireguardProfile.String(), qr.M, qr.Auto)
		if err != nil {
			log.Println(username, remoteAddr, "failed to generate qr code:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		image, err = barcode.Scale(image, 400, 400)
		if err != nil {
			log.Println(username, remoteAddr, "failed to output barcode bytes:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		var buff bytes.Buffer
		err = png.Encode(&buff, image)
		if err != nil {
			log.Println(user.Username, remoteAddr, "encoding mfa secret as png failed:", err)
			http.Error(w, "Unknown error", http.StatusInternalServerError)
			return
		}

		qrCodeBytes := resources.QrCodeEnrolmentDisplay{
			ImageData: template.URL("data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes())),
			Username:  username,
		}

		err = resources.Render("qrcode_enrolment.html", w, &qrCodeBytes)
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to show qr code wireguard config:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

	} else {

		w.Header().Set("Content-Disposition", "attachment; filename="+data.GetWireguardConfigName())

		err = resources.RenderWithFuncs("wgconf_enrolment.tmpl", w, &wireguardInterface, template.FuncMap{
			"StringsJoin": strings.Join,
			"Unescape":    func(s string) template.HTML { return template.HTML(s) },
		})
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	//Finish registration process
	err = data.FinaliseRegistration(key)
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

func (es *EnrolmentServer) reachability(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "text/plain")

	isDrained, err := data.IsDrained(data.GetServerID().String())
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

func New(firewall *router.Firewall, errChan chan<- error) (*EnrolmentServer, error) {
	if firewall == nil {
		panic("firewall was nil")
	}

	var es EnrolmentServer
	es.firewall = firewall

	public := http.NewServeMux()
	public.HandleFunc("GET /static/", utils.EmbeddedStatic(styling.Static))
	public.HandleFunc("GET /reachability", es.reachability)
	public.HandleFunc("GET /register_device", es.registerDevice)

	if err := autotls.Do.DynamicListener(data.Public, public); err != nil {
		return nil, err
	}

	log.Println("[ENROLMENT] Public enrolment listening: ", config.Values.Webserver.Public.ListenAddress)

	return &es, nil

}
