package main

import (
	"connectivly/server"
	"connectivly/storage/sqlite"
	"log"
	"os"
	"strconv"

	"connectivly/config"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
	zl "github.com/rs/zerolog/log"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	zl.Logger = zl.With().Caller().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr})

	kong.Parse(&config.CLI)

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
