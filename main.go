package main

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/leantar/backend/config"
	"github.com/leantar/backend/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"os/signal"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if err := run(); err != nil {
		log.Fatal().Caller().Err(err).Msg("failed to run backend")
	}
}

func run() error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	var cfg config.GlobalConfig
	err := config.FromEnv(&cfg)
	if err != nil {
		return err
	}

	err = validator.New().Struct(cfg)
	if err != nil {
		return fmt.Errorf("validation of config failed: %w", err)
	}

	s, err := server.New(cfg.Server)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}
	go func() {
		err := s.Run()
		if err != nil {
			panic(err)
		}
	}()

	<-stop

	return s.Stop()
}
