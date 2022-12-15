package server

import (
	"github.com/labstack/echo/v4"
	"net/http"
)

func (s *Server) handleGetEmails() echo.HandlerFunc {
	type output struct {
		Emails []string `json:"emails"`
	}

	return func(c echo.Context) error {
		if c.Request().Header.Get("X-API-KEY") != s.cfg.AdminApiKey {
			return c.NoContent(http.StatusForbidden)
		}

		s.mutex.Lock()
		defer s.mutex.Unlock()

		emails := make([]string, 0)
		for email := range s.userData {
			emails = append(emails, email)
		}

		return c.JSON(http.StatusOK, output{Emails: emails})
	}
}
