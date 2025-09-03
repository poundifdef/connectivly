package main

import (
	"connectivly/server"
	"connectivly/storage/sqlite"
	"os"
	"strconv"

	"connectivly/config"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.With().Caller().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr})

	kong.Parse(&config.CLI)

	storage, err := sqlite.NewSQLiteStorage(
		config.CLI.Serve.SQLitePath,
		config.CLI.Serve.RedirectURL,
		config.CLI.Serve.APIKey,
		config.CLI.Serve.ProviderName,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize storage")
	}

	authServer := server.AuthServer{
		Storage:     storage,
		Issuer:      config.CLI.Serve.Issuer,
		UserinfoURL: config.CLI.Serve.UserinfoURL,
	}
	app := authServer.GetAppFiber()

	log.Info().Msg("Listening on :" + strconv.Itoa(config.CLI.Serve.Port))

	app.Listen(":" + strconv.Itoa(config.CLI.Serve.Port))
}
