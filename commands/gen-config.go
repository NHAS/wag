package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/NHAS/wag/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type genconfig struct {
	fs    *flag.FlagSet
	blank bool
	path  string
}

func GenConfig() *genconfig {
	gc := &genconfig{
		fs: flag.NewFlagSet("gen-config", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.path, "out", "", "output filename")

	gc.fs.Bool("blank", false, "Create a new enrolment token")
	return gc
}

func (g *genconfig) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *genconfig) Name() string {

	return g.fs.Name()
}

func (g *genconfig) PrintUsage() {
	fmt.Println("Usage of gen-config:")
	fmt.Println("  Output a fully formed wag configuration file with sane defaults")
	fmt.Println("  -blank\tdont ask questions, just write a blank configuration file to local directory")
	fmt.Println("  -out\tlocation to write resulting configuration file (otherwise defaults to config.json.<date>)")
}

func (g *genconfig) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "blank":
			g.blank = true
		}
	})

	return nil
}

func (g *genconfig) Run() error {

	if g.path == "" {
		g.path = "config.json." + time.Now().Format("20060102150405")
	}

	var (
		err error
		c   config.Config
	)
	if !g.blank {
		//Ask questions
		c.Lockout = 5

		fmt.Print("support email: ")
		fmt.Scanf("%s", &c.HelpMail)

		c.MaxSessionLifetimeMinutes = 1440 // 24 hours
		c.SessionInactivityTimeoutMinutes = 60

		fmt.Print("external ip address or domain name (where wireguard clients will send data): ")
		fmt.Scanf("%s", &c.ExternalAddress)
		if c.ExternalAddress == "" {
			fmt.Print("no exteranl address supplied, clients will not be able to talk back with the generated configuration")
		}

		c.Webserver.Public.ListenAddress = ":8080"
		fmt.Print("listen address of registration endpoint (format: ip:port or :port, e.g 127.0.0.1:8080 or :8080, default: :8080): ")
		fmt.Scanf("%s", &c.Webserver.Public.ListenAddress)

		c.Wireguard.Address = "10.1.2.1/24"
		fmt.Print("enter vpn subnet (default 10.1.2.1/24): ")
		fmt.Scanf("%s", &c.Wireguard.Address)

		tunnelPort := 80
		fmt.Print("vpn tunnel port (default 80): ")
		fmt.Scanf("%d", &tunnelPort)

		c.Webserver.Tunnel.Port = fmt.Sprintf("%d", tunnelPort)

		c.DatabaseLocation = "devices.db"

		c.Issuer = "WAG"
		fmt.Print("name of organisation (name of 2fa entry, defaults to wag): ")
		fmt.Scanf("%s", &c.Issuer)

		c.Wireguard.DevName = "wg0"
		_, err = net.InterfaceByName(c.Wireguard.DevName)
		if err == nil {
			fmt.Print("wireguard device name (wg0 is taken): ")
			fmt.Scanf("%s", &c.Wireguard.DevName)
		}

		k, err := wgtypes.GenerateKey()
		if err != nil {
			return err
		}

		c.Wireguard.PrivateKey = k.String()
		c.Wireguard.ListenPort = 5920
		c.Wireguard.MTU = 1420
		c.Wireguard.PersistentKeepAlive = 25

		c.Acls.Groups = make(map[string][]string)
		c.Acls.Policies = make(map[string]*config.Acl)

	}

	result, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}

	fmt.Printf("\nnew config written to '%s', add some acls under Acls.Policies to start\n", g.path)

	return ioutil.WriteFile(g.path, result, 0700)
}
