package data

import (
	"database/sql"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/data/migrations"
	_ "github.com/mattn/go-sqlite3"
)

var (
	database               *sql.DB
	allowedTokenCharacters = regexp.MustCompile(`[a-zA-Z0-9\-\_\.]+`)
)

func copyFile(src, dst string) error {

	fin, err := os.Open(src)
	if err != nil {
		return err
	}
	defer fin.Close()

	fout, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer fout.Close()

	_, err = io.Copy(fout, fin)

	if err != nil {
		return err
	}

	return nil
}

func Load(path string) error {

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}

	database = db

	can, err := migrations.Can(db)
	if err != nil {
		return err
	}

	if can && !strings.HasPrefix(path, "file::memory:") {
		backupPath := path + "." + time.Now().Format("20060102150405") + ".bak"
		log.Println("can do migrations, backing up database to ", backupPath)

		err := copyFile(path, backupPath)
		if err != nil {
			return err
		}
	}

	return migrations.Do(db)
}
