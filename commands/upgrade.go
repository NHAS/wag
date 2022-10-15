package commands

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/NHAS/wag/control"
)

type upgrade struct {
	fs             *flag.FlagSet
	force          bool
	manual         bool
	newVersionPath string
	hash           string
}

func Upgrade() *upgrade {
	gc := &upgrade{
		fs: flag.NewFlagSet("upgrade", flag.ContinueOnError),
	}

	gc.fs.Bool("force", false, "Disable version compatiablity checks")
	gc.fs.Bool("manual", false, "Shutdown the server in upgrade mode but will not copy or automatically check the new wag binary")

	gc.fs.StringVar(&gc.newVersionPath, "path", "", "File path to new wag executable")
	gc.fs.StringVar(&gc.hash, "hash", "", "Version hash from new wag version (find this by doing ./wag version -local)")

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
	fmt.Println("  THIS WILL NOT RESTART THE SERVER AFTER SHUTDOWN")
	g.fs.PrintDefaults()
}

func (g *upgrade) Check() error {
	g.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "force":
			g.force = true
		case "manual":
			g.manual = true
		}
	})

	if g.manual && g.newVersionPath != "" {
		return errors.New("cannot specify both -manual and -path")
	}

	if g.manual {
		if !g.force {
			if g.hash == "" {
				fmt.Print("Enter bpf version hash (find with wag version -local): ")
				fmt.Scanf("%s", &g.hash)
			}

			currentHash, err := control.GetBPFVersion()
			if err != nil {
				return err
			}

			if g.hash != currentHash {
				return errors.New("new version has a different version of the eBPF XDP firewall.\nWe cannot reload the XDP firewall on the fly. Please shutdown wag and place binary manually.\nOtherwise it will break in unpredicable ways.")
			}
		}
		return nil
	}

	if !g.manual && g.newVersionPath == "" {
		return errors.New("to upgrade wag a either a new version must be specified (-path), or -manual must be specified")
	}

	if _, err := os.Stat(g.newVersionPath); err != nil {
		return errors.New("error reading " + g.newVersionPath + ":" + err.Error())
	}

	if !g.force {
		fmt.Print("Checking new version compatibility...")
		output, err := exec.Command(g.newVersionPath, "version", "-local").CombinedOutput()
		if err != nil {
			return err
		}

		lines := bytes.Split(output, []byte("\n"))
		if len(lines) != 4 {
			return errors.New("the number of version lines from the new version does not match expected")
		}

		if !bytes.Equal(lines[0], []byte("local")) {
			return errors.New("new program did not report local version")
		}

		hash, err := control.GetBPFVersion()
		if err != nil {
			return err
		}

		if !bytes.Equal(bytes.TrimSpace(lines[2]), []byte("Hash: "+hash)) {
			return errors.New("new version has a different version of the eBPF XDP firewall.\nWe cannot reload the XDP firewall on the fly. Please shutdown wag and place binary manually.\nOtherwise it will break in unpredicable ways.")
		}
		fmt.Println("Done")
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
	control.Shutdown(false)
	fmt.Println("Done")

	if g.newVersionPath != "" {

		currentPath, _ := os.Executable()

		err := os.Rename(g.newVersionPath, currentPath)
		if err != nil {
			return err
		}
	}

	return nil
}

const wag_was_upgraded = "/tmp/wag-upgrade"
