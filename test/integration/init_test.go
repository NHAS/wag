package integration

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NHAS/wag/commands"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/pkg/control/wagctl"
)

var ctrl *wagctl.CtrlClient

func TestMain(m *testing.M) {

	startCommand := commands.Start()
	startCommand.Config = "resources/integration_config.json"
	startCommand.NoIptables = true

	os.MkdirAll("temp", 0777)

	err := startCommand.Check()
	if err != nil {
		log.Println("check failed, this should be a valid config: ", err)
		os.Exit(1)
	}

	ready := make(chan bool)

	startCommand.DB.RegisterClusterHealthListener(func(status string) {
		if status == "healthy" {
			ready <- true
		}
	})

	go func() {
		err = startCommand.Run()
		if err != nil {
			os.RemoveAll("temp")

			log.Fatal("could not start integration wag: ", err)

		}
	}()

	<-ready

	for i := 0; i < 20; i++ {
		ctrl = wagctl.NewControlClient(config.Values.Socket)

		version, err := ctrl.GetVersion()
		if err != nil {
			if strings.Contains(err.Error(), "no such file or directory") {
				time.Sleep(1 * time.Second)
				continue
			}

			log.Println("Error connecting to wag socket: ", err)
			os.Exit(2)
		}

		log.Println("connected tests to: ", version)
		break
	}

	code := m.Run()

	os.RemoveAll("temp")

	os.Exit(code)

}
