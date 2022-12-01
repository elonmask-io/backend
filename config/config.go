package config

type ServerConfig struct {
	RPOrigin      string `env:"RP_ORIGIN" validate:"required"`
	RPID          string `env:"RP_ID" validate:"required"`
	BackendPort   uint16 `env:"BACKEND_PORT" validate:"required"`
	InfuraAddress string `env:"INFURA_ADDRESS" validate:"required"`
	PrivateKeyD   string `env:"PRIVATE_KEY_D_HEX" validate:"required"`
}

type GlobalConfig struct {
	Server ServerConfig
}
