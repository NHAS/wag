package data

import (
	"database/sql"
	"net"
	"testing"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/data/migrations"
	_ "github.com/mattn/go-sqlite3"
)

func TestMigrationFromNew(t *testing.T) {
	if err := config.Load("../config/test_in_memory_db.json"); err != nil {
		t.Fatal(err)
	}

	err := Load("file::memory:")
	if err != nil {
		t.Fatal(err)
	}
}

func TestMigrationFromVersion1(t *testing.T) {
	if err := config.Load("../config/test_in_memory_db.json"); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS RegistrationTokens ( token string primary key, username string not null unique )")
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS Totp ( address string primary key, publickey string not null unique, username string not null unique, url string not null unique, enforcing string, attempts integer not null )")
	if err != nil {
		t.Fatal(err)
	}

	//Leaves enforcing null
	_, err = db.Exec(`
	INSERT INTO
		Totp (address, publickey, username, url, attempts)
	VALUES
		(?, ?, ?, ?, ?)`, "192.168.1.1", "blank", "toaster", "no", 0)
	if err != nil {
		t.Fatal(err)
	}

	canUpgrade, err := migrations.Can(db)
	if err != nil {
		t.Fatal(err)
	}

	if !canUpgrade {
		t.Fatal("database should be upgradable")
	}

	err = Load("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}

	d, err := GetDeviceByAddress("192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}

	if d.Username != "toaster" || d.Address != "192.168.1.1" || d.Publickey != "blank" {
		t.Fatalf("details wrong: %+v", d)
	}

	err = UpdateDeviceEndpoint("192.168.1.1", &net.UDPAddr{Port: 4444, IP: net.ParseIP("192.168.1.1")})
	if err != nil {
		t.Fatal(err)
	}

}
