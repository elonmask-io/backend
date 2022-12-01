package server

import (
	"context"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"math/big"
	"net/http"
)

func (s *Server) handleGetTransactions() echo.HandlerFunc {
	type response struct {
		Transactions []types.Transaction `json:"transactions"`
	}

	return func(c echo.Context) error {
		claims := c.Get("claims").(jwt.MapClaims)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		userData, ok := s.userData[claims["username"].(string)]
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "user does not exist")
		}

		res := response{
			Transactions: make([]types.Transaction, 0),
		}

		for _, hash := range userData.transactions {
			tx, _, err := s.client.TransactionByHash(c.Request().Context(), hash)
			if err != nil {
				log.Error().Caller().Err(err).Msg("failed to get transaction by hash")
				return echo.NewHTTPError(http.StatusInternalServerError)
			}

			res.Transactions = append(res.Transactions, *tx)
		}

		return c.JSON(http.StatusOK, res)
	}
}

func (s *Server) handleTransactionInitialize() echo.HandlerFunc {
	return func(c echo.Context) error {
		claims := c.Get("claims").(jwt.MapClaims)

		s.mutex.Lock()
		defer s.mutex.Unlock()
		userData, ok := s.userData[claims["username"].(string)]
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "user does not exist")
		}

		options, session, err := s.webAuthn.BeginLogin(&userData.user)
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to begin tx")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		userData.transactionSession = session

		return c.JSON(http.StatusOK, options)
	}
}

func (s *Server) handleTransactionFinalize() echo.HandlerFunc {
	type transactionResponse struct {
		TransactionHash string `json:"transaction_hash"`
	}

	return func(c echo.Context) error {
		receiverAddress := c.Request().Header.Get("x-receiver-address")
		if receiverAddress == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing x-receiver-address header")
		}

		amount := c.Request().Header.Get("x-amount")
		if amount == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing x-amount header")
		}

		claims := c.Get("claims").(jwt.MapClaims)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		userData, ok := s.userData[claims["username"].(string)]
		if !ok || userData.transactionSession == nil {
			return echo.NewHTTPError(http.StatusBadRequest, "must call transaction-init first")
		}

		_, err := s.webAuthn.FinishLogin(&userData.user, *userData.loginSession, c.Request())
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to finish tx")
			return echo.NewHTTPError(http.StatusBadRequest, "failed to verify credentials")
		}

		userData.transactionSession = nil

		hash, err := s.transferETH(*userData.privateKey, receiverAddress, amount, c.Request().Context())
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to send tx")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		userData.transactions = append(userData.transactions, hash)

		return c.JSON(http.StatusOK, transactionResponse{TransactionHash: hash.Hex()})
	}
}

func (s *Server) transferETH(senderSk ecdsa.PrivateKey, receiverAddress string, amountInWei string, ctx context.Context) (common.Hash, error) {
	fromAddress := crypto.PubkeyToAddress(senderSk.PublicKey)

	nonce, err := s.client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return common.Hash{}, err
	}

	value := new(big.Int)
	value.SetString(amountInWei, 10)
	gasLimit := uint64(21000)         // in units
	tipCap := big.NewInt(2000000000)  // maxPriorityFeePerGas = 2 Gwei
	feeCap := big.NewInt(20000000000) // maxFeePerGas = 20 Gwei

	toAddress := common.HexToAddress(receiverAddress)

	chainID, err := s.client.NetworkID(ctx)
	if err != nil {
		return common.Hash{}, err
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
		return common.Hash{}, err
	}

	return signedTx.Hash(), s.client.SendTransaction(ctx, signedTx)
}
