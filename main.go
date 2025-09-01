package main

import (
	"connectivly/server"
	"connectivly/storage/sqlite"
	"log"
	"strconv"

	"connectivly/config"

	"github.com/alecthomas/kong"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	ctx := kong.Parse(&config.CLI)
	log.Println(ctx)

	storage, err := sqlite.NewSQLiteStorage(config.CLI.Serve.SQLitePath, config.CLI.Serve.RedirectURL)
	if err != nil {
		log.Fatal(err)
	}

	authServer := server.AuthServer{
		Storage:     storage,
		Issuer:      config.CLI.Serve.Issuer,
		UserinfoURL: config.CLI.Serve.UserinfoURL,
	}
	app := authServer.GetAppFiber()

	log.Println("Listening on :" + strconv.Itoa(config.CLI.Serve.Port))

	app.Listen(":" + strconv.Itoa(config.CLI.Serve.Port))
}
