package db

import (
	"database/sql"
	"errors"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

type Row struct {
	*sql.Row
}

func Init() {
	var err error

	// Подключение к БД
	db, err = sql.Open("sqlite3", "auth.db")
	if err != nil {
		panic(err)
	}

	// При необходимости, создаю таблицу
	err = Exec(`CREATE TABLE IF NOT EXISTS users (
		uuid TEXT PRIMARY KEY,
		email TEXT UNIQUE,
		password TEXT,
		salt TEXT
	)`)
	if err != nil {
		panic(err)
	}
}

var ErrNoRows = errors.New("sql: no rows in result set")

func (row Row) Scan(dest ...any) error {
	return row.Row.Scan(dest...)
}

func QueryRow(query string, args ...any) Row {
	return Row{db.QueryRow(query, args...)}
}

func Exec(query string, args ...any) (err error) {
	_, err = db.Exec(query, args...)
	return
}
