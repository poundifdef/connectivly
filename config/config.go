package config

var CLI struct {
	Serve struct {
		Port        int    `name:"port" env:"CONNECTIVLY_PORT" default:"3000"`
		RedirectURL string `name:"redirect-url" help:"Redirect URL." env:"CONNECTIVLY_REDIRECT_URL"`
		UserinfoURL string `name:"userinfo-url" help:"Userinfo URL." env:"CONNECTIVLY_USERINFO_URL"`
		SQLitePath  string `name:"sqlite-path" env:"CONNECTIVLY_SQLITE_PATH" type:"path" default:"./connectivly.db"`
		Issuer      string `name:"issuer" env:"CONNECTIVLY_ISSUER" default:"http://localhost:3000"`
	} `cmd:"serve" help:"Starts Connectivly server."`
}
