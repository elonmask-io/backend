package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/labstack/echo/v4"
	"github.com/leantar/backend/config"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type userData struct {
	user                User
	registrationSession *webauthn.SessionData
	loginSession        *webauthn.SessionData
	transactionSession  *webauthn.SessionData
	privateKey          *ecdsa.PrivateKey
	transactions        []common.Hash
	contacts            map[string]string
}

type Server struct {
	echo     *echo.Echo
	cfg      config.ServerConfig
	userData map[string]*userData
	webAuthn *webauthn.WebAuthn
	mutex    *sync.Mutex
	client   *ethclient.Client
	sk       *ecdsa.PrivateKey
}

func New(cfg config.ServerConfig) (*Server, error) {
	e := echo.New()
	e.Server.ReadTimeout = 5 * time.Second
	e.Server.WriteTimeout = 30 * time.Second
	e.Server.IdleTimeout = 120 * time.Second

	//Restore sk from hex string
	dBytes, err := hex.DecodeString(cfg.PrivateKeyD)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	d := new(big.Int)
	d.SetBytes(dBytes)

	sk := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: crypto.S256(),
		},
		D: d,
	}
	sk.PublicKey.X, sk.PublicKey.Y = crypto.S256().ScalarBaseMult(dBytes)

	//prepare webauthn
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "elon-mask",
		RPID:          cfg.RPID,
		RPOrigin:      cfg.RPOrigin,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn from config: %w", err)
	}

	//connect to infura node
	client, err := ethclient.Dial(cfg.InfuraAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to infura: %w", err)
	}

	return &Server{
		echo:     echo.New(),
		cfg:      cfg,
		userData: make(map[string]*userData),
		webAuthn: webAuthn,
		mutex:    &sync.Mutex{},
		client:   client,
		sk:       &sk,
	}, nil
}

func (s *Server) Run() (err error) {
	s.registerRoutes()

	err = s.echo.Start("0.0.0.0:8080")
	if err == http.ErrServerClosed {
		err = nil
	}

	return
}

func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return s.echo.Shutdown(ctx)
}
