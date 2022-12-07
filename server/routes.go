package server

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"
)

func (s *Server) registerRoutes() {
	s.echo.Use(s.cors())
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

func (s *Server) cors() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			res := c.Response()
			preflight := req.Method == http.MethodOptions

			methods := []string{http.MethodGet, http.MethodPost, http.MethodOptions}

			res.Header().Add(echo.HeaderVary, echo.HeaderOrigin)
			res.Header().Add(echo.HeaderAccessControlAllowMethods, strings.Join(methods, ","))
			res.Header().Add(echo.HeaderAccessControlAllowOrigin, s.cfg.RPOrigin)
			res.Header().Add(echo.HeaderAccessControlAllowCredentials, "true")
			res.Header().Add(echo.HeaderAccessControlAllowHeaders, "*")

			if !preflight {
				return next(c)
			}

			return c.NoContent(http.StatusNoContent)
		}
	}
}
