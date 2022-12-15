package server

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"
)

func (s *Server) checkAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			bearer := c.Request().Header.Get("Authorization")

			if bearer == "" {
				return echo.NewHTTPError(http.StatusBadRequest, "missing bearer token")
			}

			parts := strings.Split(bearer, "Bearer")
			if len(parts) != 2 {
				return echo.NewHTTPError(http.StatusBadRequest, "missing bearer token")
			}

			token := strings.TrimSpace(parts[1])
			if len(token) < 1 {
				return echo.NewHTTPError(http.StatusBadRequest, "missing bearer token")
			}

			claims, ok := s.validateJWT(token)
			if !ok {
				return echo.NewHTTPError(http.StatusBadRequest, "invalid bearer token")
			}

			c.Set("claims", claims)

			return next(c)
		}
	}
}
