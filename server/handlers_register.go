package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"math/big"
	"net/http"
)

func (s *Server) handleRegisterInitialize() echo.HandlerFunc {
	return func(c echo.Context) error {
		username := c.Request().Header.Get("x-username")
		if username == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing x-username header")
		}

		s.mutex.Lock()
		defer s.mutex.Unlock()
		_, exists := s.userData[username]
		if exists {
			return echo.NewHTTPError(http.StatusConflict, "user already exists")
		}

		user := NewUser(username, username)

		registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
			credCreationOpts.Parameters = []protocol.CredentialParameter{
				{
					Type:      "public-key",
					Algorithm: -7,
				},
				{
					Type:      "public-key",
					Algorithm: -257,
				},
			}
			credCreationOpts.Attestation = protocol.PreferNoAttestation

			credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
		}

		options, session, err := s.webAuthn.BeginRegistration(&user, registerOptions)
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to begin registration")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		s.userData[username] = &userData{
			user:                user,
			registrationSession: session,
			contacts:            make(map[string]string),
			transactions:        make([]common.Hash, 0),
		}

		return c.JSON(http.StatusOK, options)
	}
}

func (s *Server) handleRegisterFinalize() echo.HandlerFunc {
	type tokenResponse struct {
		Token string `json:"token"`
	}

	return func(c echo.Context) error {
		username := c.Request().Header.Get("x-username")
		if username == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing x-username header")
		}

		s.mutex.Lock()
		defer s.mutex.Unlock()
		userData, ok := s.userData[username]
		if !ok || userData.registrationSession == nil {
			return echo.NewHTTPError(http.StatusBadRequest, "must call register-init first")
		}

		credential, err := s.webAuthn.FinishRegistration(&userData.user, *userData.registrationSession, c.Request())
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err)
		}

		userData.user.AddCredential(*credential)
		userData.registrationSession = nil

		sk, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to generate ecdsa key")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		userData.privateKey = sk

		if err := s.transferInitialETH(sk.PublicKey, c.Request().Context()); err != nil {
			log.Error().Caller().Err(err).Msg("failed to send initial eth to new user")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		token, err := s.createJWT(username, crypto.PubkeyToAddress(sk.PublicKey).Hex())
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to create jwt")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		return c.JSON(http.StatusOK, tokenResponse{Token: token})
	}
}

func (s *Server) transferInitialETH(receiverPk ecdsa.PublicKey, ctx context.Context) error {
	fromAddress := crypto.PubkeyToAddress(s.sk.PublicKey)

	nonce, err := s.client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return err
	}

	value := big.NewInt(10000000000000000)
	gasLimit := uint64(21000)         // in units
	tipCap := big.NewInt(2000000000)  // maxPriorityFeePerGas = 2 Gwei
	feeCap := big.NewInt(20000000000) // maxFeePerGas = 20 Gwei

	toAddress := crypto.PubkeyToAddress(receiverPk)

	chainID, err := s.client.NetworkID(ctx)
	if err != nil {
		return err
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasFeeCap: feeCap,
		GasTipCap: tipCap,
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     value,
		Data:      make([]byte, 0),
	})

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), s.sk)
	if err != nil {
		return err
	}

	return s.client.SendTransaction(ctx, signedTx)
}
