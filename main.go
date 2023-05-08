package main

import (
	"connectivly/server"
	"connectivly/storage/sqlite"
	"log"
	"os"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	redirectUrl, found := os.LookupEnv("CONNECTIVLY_REDIRECT_URL")
	if !found {
		log.Fatal("Environment variable CONNECTIVLY_REDIRECT_URL required")
	}

	s, _ := sqlite.NewSQLiteStorage("connectivly.db", redirectUrl)

	authServer := server.AuthServer{Storage: s}
	app := authServer.GetAppFiber()

	log.Println("Listening on http://localhost:3000")

	app.Listen(":3000")
}
