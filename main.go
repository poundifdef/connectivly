package main

import (
	"log"
	"os"

	"connectivly/server"
	"connectivly/storage"
	"connectivly/storage/redis"
	"connectivly/storage/sqlite"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	redirectUrl, found := os.LookupEnv("CONNECTIVLY_REDIRECT_URL")
	if !found {
		log.Fatal("Environment variable CONNECTIVLY_REDIRECT_URL required")
	}

	storageType := os.Getenv("STORAGE")

	var storage storage.Storage

	switch storageType {
	case "sqlite":
		storage, _ = sqlite.NewSQLiteStorage("connectivly.db", redirectUrl)
	case "redis":
		redisConnectionString := os.Getenv("REDIS_CONNECTION_STRING")
		storage, _ = redis.NewRedisStorage(redisConnectionString, redirectUrl)
	}

	authServer := server.AuthServer{Storage: storage}
	app := authServer.GetAppFiber()

	log.Println("Listening on :3000")

	app.Listen(":3000")
}
