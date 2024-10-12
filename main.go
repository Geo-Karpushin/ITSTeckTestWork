package main

import (
	"fmt"
	"os"
	"strconv"
	"testwork/auth"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Укажите порт для сервера")
		return
	}

	_, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Порт должен быть числом")
		return
	}

	auth.Init("supersecretkey", os.Args[1])
}
