package server

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"net/http"
)

type Contact struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

func (s *Server) handleCreateContact() echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("claims").(jwt.MapClaims)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		userData, ok := s.userData[claims["username"].(string)]
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "user does not exist")
		}

		var in Contact
		if err := c.Bind(&in); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
		}

		userData.contacts[in.Name] = in.PublicKey

		return c.String(http.StatusOK, "")
	}
}

func (s *Server) handleGetContacts() echo.HandlerFunc {
	type output struct {
		Contacts []Contact `json:"contacts"`
	}

	return func(c echo.Context) error {
		claims := c.Get("claims").(jwt.MapClaims)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		data, ok := s.userData[claims["username"].(string)]
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "user does not exist")
		}

		out := output{
			Contacts: make([]Contact, 0),
		}

		for name, pk := range data.contacts {
			out.Contacts = append(out.Contacts, Contact{
				Name:      name,
				PublicKey: pk,
			})
		}

		return c.JSON(http.StatusOK, out)
	}
}
