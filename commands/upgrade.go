package commands

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/NHAS/wag/control"
)

type upgrade struct {
	fs   *flag.FlagSet
	hash string
}

func Upgrade() *upgrade {
	gc := &upgrade{
		fs: flag.NewFlagSet("upgrade", flag.ContinueOnError),
	}

	gc.fs.StringVar(&gc.hash, "hash", "", "version of bpf program in the new wag version, find this with ./wag version -local on your new version of wag, if not specified will be asked for via stdin")

	return gc
}

func (g *upgrade) FlagSet() *flag.FlagSet {
	return g.fs
}

func (g *upgrade) Name() string {

	return g.fs.Name()
}

func (g *upgrade) PrintUsage() {
	fmt.Println("Usage of upgrade:")
	fmt.Println("  Pin all ebpf programs and then shutdown wag server while leaving the XDP firewall online")
	g.fs.PrintDefaults()
}

func (g *upgrade) Check() error {

	if g.hash == "" {
		fmt.Print("Enter bpf version hash (find with wag version -local): ")
		fmt.Scanf("%s", &g.hash)
	}

	currentHash, err := control.GetBPFVersion()
	if err != nil {
		return err
	}

	if g.hash != currentHash {
		return errors.New("the new program has a different version of the eBPF XDP firewall currently\nwe cannot reload this on the fly. Please shutdown wag, and place binary manually.\n This will break otherwise in unpredicable ways.")
	}

	return nil
}

func (g *upgrade) Run() error {
	fmt.Print("Pinning ebpf assets....")
	if err := control.PinBPF(); err != nil {
		return err
	}
	fmt.Println("Done")

	fmt.Print("Writing iptables ignore tmp file....")
	err := os.WriteFile(wag_was_upgraded, []byte("0"), 0600)
	if err != nil {
		return err
	}
	fmt.Println("Done")

	fmt.Println("Ready to replace with new version")

	fmt.Print("Shutting down server...")
	if err := control.Shutdown(false); err != nil {
		return err
	}
	fmt.Println("Done")

	return nil
}

const wag_was_upgraded = "/tmp/wag-upgrade"
