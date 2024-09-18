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

	storage, err := sqlite.NewSQLiteStorage("connectivly.db", redirectUrl)
	if err != nil {
		log.Fatal(err)
	}

	authServer := server.AuthServer{Storage: storage}
	app := authServer.GetAppFiber()

	log.Println("Listening on :3000")

	app.Listen(":3000")
}
