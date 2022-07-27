package control

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"wag/firewall"
)

const controlSocket = "/tmp/wag.sock"

type msg struct {
	Type string
	Arg  string
}

type result struct {
	Type string
	Text string
}

func handler(con net.Conn) {
	dec := json.NewDecoder(con)
	defer con.Close()
	for {
		var currentMessage msg
		err := dec.Decode(&currentMessage)
		if err != nil {
			return
		}

		switch currentMessage.Type {
		case "block":
			err := block(con, currentMessage.Arg)
			if err != nil {
				return
			}
		case "sessions":
			m := firewall.GetAllAllowed()
			r := result{Type: "OK"}

			for dev, endpoint := range m {
				r.Text += fmt.Sprintf("%s,%s\n", dev, endpoint)
			}

			result, _ := json.Marshal(&r)

			_, err := con.Write([]byte(result))
			if err != nil {
				return
			}
		}
	}
}

func block(con net.Conn, address string) error {
	r := result{}
	err := firewall.Block(address)
	//If iptables cannot find the rule, it reports badrule, which is fine. Means its not forwarding the devices traffic anyway
	if err != nil && !strings.Contains("Bad rule", err.Error()) {
		r.Type = "FAIL"
		r.Text = err.Error()
		result, _ := json.Marshal(&r)
		_, err := con.Write(result)
		if err != nil {
			return err
		}
	}

	r.Type = "OK"
	r.Text = address

	result, _ := json.Marshal(&r)

	_, err = con.Write(result)
	if err != nil {
		return err
	}
	return nil
}

func StartControlSocket() error {
	l, err := net.Listen("unix", controlSocket)
	if err != nil {

		return err
	}

	if err := os.Chmod(controlSocket, 0700); err != nil {
		return err
	}

	log.Println("Started control socket: \n\t\t\t", controlSocket)

	go func() {
		defer l.Close()

		for {
			conn, err := l.Accept()
			if err != nil {
				log.Println("accept error:", err)
				continue
			}

			go handler(conn)
		}
	}()

	return nil
}

func TearDown() {
	err := os.Remove(controlSocket)
	if err != nil {
		log.Println(err)
	}
}
