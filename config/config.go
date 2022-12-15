package config

type ServerConfig struct {
	RPOrigin      string `env:"RP_ORIGIN" validate:"required"`
	RPID          string `env:"RP_ID" validate:"required"`
	InfuraAddress string `env:"INFURA_ADDRESS" validate:"required"`
	MoralisAPIKey string `env:"MORALIS_API_KEY" validate:"required"`
	PrivateKeyD   string `env:"PRIVATE_KEY_D_HEX" validate:"required"`
	AdminApiKey   string `env:"ADMIN_API_KEY" validate:"required"`
	SecretKey     string `env:"SECRET_KEY" validate:"required"`
}

type GlobalConfig struct {
	Server ServerConfig
}
