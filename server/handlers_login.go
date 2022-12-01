package server

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"net/http"
)

func (s *Server) handleLoginInitialize() echo.HandlerFunc {
	return func(c echo.Context) error {
		username := c.Request().Header.Get("x-username")
		if username == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing x-username header")
		}

		s.mutex.Lock()
		defer s.mutex.Unlock()
		userData, ok := s.userData[username]
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "user does not exist")
		}

		options, session, err := s.webAuthn.BeginLogin(&userData.user)
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to begin login")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		userData.loginSession = session

		return c.JSON(http.StatusOK, options)
	}
}

func (s *Server) handleLoginFinalize() echo.HandlerFunc {
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
		if !ok || userData.loginSession == nil {
			return echo.NewHTTPError(http.StatusBadRequest, "must call login-init first")
		}

		_, err := s.webAuthn.FinishLogin(&userData.user, *userData.loginSession, c.Request())
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to finish login")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		userData.loginSession = nil

		token, err := s.createJWT(username, crypto.PubkeyToAddress(userData.privateKey.PublicKey).Hex())
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to create jwt")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		return c.JSON(http.StatusOK, tokenResponse{Token: token})
	}
}
