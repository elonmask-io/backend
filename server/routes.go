package server

import (
	"github.com/labstack/echo/v4/middleware"
	"net/http"
)

func (s *Server) registerRoutes() {
	s.echo.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{s.cfg.RPOrigin},
		AllowMethods:     []string{http.MethodGet, http.MethodPost},
		AllowCredentials: true,
	}))
	s.echo.GET("/register-init", s.handleRegisterInitialize())
	s.echo.POST("/register-finalize", s.handleRegisterFinalize())

	s.echo.GET("/login-init", s.handleLoginInitialize())
	s.echo.POST("/login-finalize", s.handleLoginFinalize())

	s.echo.GET("/transaction-init", s.handleTransactionInitialize(), checkAuth())
	s.echo.POST("/transaction-finalize", s.handleTransactionFinalize(), checkAuth())

	s.echo.POST("/create-contact", s.handleCreateContact(), checkAuth())
	s.echo.GET("/get-contacts", s.handleGetContacts(), checkAuth())
	s.echo.GET("/get-transactions", s.handleGetTransactions(), checkAuth())
}
