package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

type MoralisTransaction struct {
	Hash                     string  `json:"hash"`
	Nonce                    string  `json:"nonce"`
	TransactionIndex         string  `json:"transaction_index"`
	FromAddress              string  `json:"from_address"`
	ToAddress                string  `json:"to_address"`
	Value                    string  `json:"value"`
	Gas                      string  `json:"gas"`
	GasPrice                 string  `json:"gas_price"`
	Input                    string  `json:"input"`
	ReceiptCumulativeGasUsed string  `json:"receipt_cumulative_gas_used"`
	ReceiptGasUsed           string  `json:"receipt_gas_used"`
	ReceiptContractAddress   string  `json:"receipt_contract_address"`
	ReceiptRoot              string  `json:"receipt_root"`
	ReceiptStatus            string  `json:"receipt_status"`
	BlockTimestamp           string  `json:"block_timestamp"`
	BlockNumber              string  `json:"block_number"`
	BlockHash                string  `json:"block_hash"`
	TransferIndex            []int64 `json:"transfer_index"`
}

type moralisResponse struct {
	Total    int64                `json:"total"`
	PageSize int64                `json:"page_size"`
	Page     int64                `json:"page"`
	Cursor   string               `json:"cursor"`
	Result   []MoralisTransaction `json:"result"`
}

var ErrInsufficientBalance = errors.New("insufficient balance for transaction and gas")

func (s *Server) fetchTransactionBatchFromMoralis(url, cursor string) (*moralisResponse, error) {
	if cursor != "" {
		url = fmt.Sprintf("%s&cursor=%s", url, cursor)
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/json")
	req.Header.Add("X-API-Key", s.cfg.MoralisAPIKey)

	res, _ := http.DefaultClient.Do(req)
	defer res.Body.Close()

	var response moralisResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("moralis api error: %w", err)
	}

	return &response, nil
}

func (s *Server) fetchAllTransactionsFromMoralis(url string) ([]MoralisTransaction, error) {
	cursor := ""
	transactions := make([]MoralisTransaction, 0)

	for {
		resp, err := s.fetchTransactionBatchFromMoralis(url, cursor)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, resp.Result...)

		cursor = resp.Cursor
		if cursor == "" {
			break
		}
	}

	return transactions, nil
}

func (s *Server) handleGetTransactions() echo.HandlerFunc {
	type response struct {
		Transactions []MoralisTransaction `json:"transactions"`
	}

	return func(c echo.Context) error {
		claims := c.Get("claims").(jwt.MapClaims)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		userData, ok := s.userData[claims["username"].(string)]
		if !ok {
			return echo.NewHTTPError(http.StatusBadRequest, "user does not exist")
		}

		url := fmt.Sprintf("https://deep-index.moralis.io/api/v2/%s?chain=goerli", crypto.PubkeyToAddress(userData.privateKey.PublicKey).Hex())

		transactions, err := s.fetchAllTransactionsFromMoralis(url)
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to fetch transactions from moralis")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		res := response{Transactions: transactions}

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

		_, err := s.webAuthn.FinishLogin(&userData.user, *userData.transactionSession, c.Request())
		if err != nil {
			log.Error().Caller().Err(err).Msg("failed to finish tx")
			return echo.NewHTTPError(http.StatusBadRequest, "failed to verify credentials")
		}

		userData.transactionSession = nil

		amountWei, err := convertAmountToWei(amount)
		if err != nil {
			log.Info().Caller().Err(err).Msg("conversion failed")
			return echo.NewHTTPError(http.StatusBadRequest, "invalid amount")
		}

		hash, err := s.transferETH(*userData.privateKey, receiverAddress, amountWei, c.Request().Context())
		if errors.Is(err, ErrInsufficientBalance) {
			log.Info().Caller().Err(err).Msg("insufficient balance")
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		} else if err != nil {
			log.Error().Caller().Err(err).Msg("failed to send tx")
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		userData.transactions = append(userData.transactions, hash)

		return c.JSON(http.StatusOK, transactionResponse{TransactionHash: hash.Hex()})
	}
}

func convertAmountToWei(amount string) (int64, error) {
	amount = strings.Replace(amount, ",", ".", 1)

	a, err := strconv.ParseFloat(amount, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to convert: %w", err)
	}

	return int64(a * 1000000000000000000), nil
}

func (s *Server) transferETH(senderSk ecdsa.PrivateKey, receiverAddress string, amountInWei int64, ctx context.Context) (common.Hash, error) {
	fromAddress := crypto.PubkeyToAddress(senderSk.PublicKey)

	nonce, err := s.client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return common.Hash{}, err
	}

	value := big.NewInt(amountInWei)
	gasLimit := uint64(21000)         // in units
	tipCap := big.NewInt(2000000000)  // maxPriorityFeePerGas = 2 Gwei
	feeCap := big.NewInt(20000000000) // maxFeePerGas = 20 Gwei

	toAddress := common.HexToAddress(receiverAddress)

	chainID, err := s.client.NetworkID(ctx)
	if err != nil {
		return common.Hash{}, err
	}

	balance, err := s.client.BalanceAt(ctx, fromAddress, nil)
	if err != nil {
		return common.Hash{}, err
	}

	requiredBalance := big.NewInt(int64(gasLimit))
	requiredBalance.Add(requiredBalance, value)

	if balance.Cmp(requiredBalance) != 1 {
		return common.Hash{}, ErrInsufficientBalance
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

	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), &senderSk)
	if err != nil {
		return common.Hash{}, err
	}

	return signedTx.Hash(), s.client.SendTransaction(ctx, signedTx)
}
