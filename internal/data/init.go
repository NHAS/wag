package data

import (
	"database/sql"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/data/migrations"
	"github.com/NHAS/wag/pkg/fsops"
	_ "github.com/mattn/go-sqlite3"
)

var (
	database               *sql.DB
	allowedTokenCharacters = regexp.MustCompile(`[a-zA-Z0-9\-\_\.]+`)
)

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

	if can && !strings.HasPrefix(path, "file::memory:") && !strings.Contains(path, "mode=memory") {
		backupPath := path + "." + time.Now().Format("20060102150405") + ".bak"
		log.Println("can do migrations, backing up database to ", backupPath)

		err := fsops.CopyFile(path, backupPath)
		if err != nil {
			return err
		}
	}

	return migrations.Do(db)
}
