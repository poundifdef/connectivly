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

	apiKey, found := os.LookupEnv("CONNECTIVLY_API_KEY")
	if !found {
		log.Fatal("Environment variable CONNECTIVLY_API_KEY required")
	}

	s, _ := sqlite.NewSQLiteStorage("connectivly.db", redirectUrl, apiKey)

	authServer := server.AuthServer{Storage: s}
	app := authServer.GetAppFiber()
	app.Listen(":3000")
}
