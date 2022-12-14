package server

import (
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

func (s *Server) createJWT(username string, pubKeyHex string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	now := time.Now()

	claims["username"] = username
	claims["pub-key"] = pubKeyHex
	claims["exp"] = now.Add(time.Hour * 24).Unix()
	claims["nbf"] = now.Unix()
	claims["iat"] = now.Unix()

	tokenString, err := token.SignedString([]byte(s.cfg.SecretKey))

	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (s *Server) validateJWT(tokenString string) (jwt.MapClaims, bool) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid token format")
		}
		return []byte(s.cfg.SecretKey), nil
	})

	if err != nil || token == nil {
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, false
	}

	return claims, claims.Valid() == nil
}
