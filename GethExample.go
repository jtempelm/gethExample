package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"log"
	"math"
	"math/big"
	"os"
)

const sourceWalletAddress = "0x26006236eaB6409D9FDECb16ed841033d6B4A6bC"                          //first account from ganache-cli -m "test"
var sourcePrivateKeyString = os.Getenv("CRYPTO_TEST_ACCOUNT_PRIVATE_KEY") //we get this from that same ganache-cli output

func main() {
	const blockchainServer = "http://localhost:8545"

	//create a new keystore containing a private key (wallet)
	myKeyStore := keystore.NewKeyStore("./wallets", keystore.StandardScryptN, keystore.StandardScryptP)
	password := os.Getenv("CRYPTO_KEYSTORE_PASSWORD")
	destinationAccount, err := myKeyStore.NewAccount(password)
	panicIfError(err)

	client, err := ethclient.Dial(blockchainServer)
	panicIfError(err)

	logBalancesForAddress(client, destinationAccount.Address)

	//collect the info we need to transfer an eth balance into it
	chainID, err := client.ChainID(context.Background())
	panicIfError(err)

	sourceAddress := common.HexToAddress(sourceWalletAddress)
	nonce := getNonceForWalletAddress(client, sourceAddress)
	transferAmount := big.NewInt(1_000_000_000_000_000_000) // in wei (1 eth)

	gasPrice, err := client.SuggestGasPrice(context.Background()) //we could decide if the given gas price is too high or not
	panicIfError(err)

	fmt.Printf("Suggested Gas Price was: %d\n", gasPrice)

	//The docs suggested this but its deprecated now
	//tx := types.NewTransaction(nonce, toAddress, transferAmount, gasLimit, gasPrice, nil)

	//make and sign the transaction the new way
	transaction := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasFeeCap: big.NewInt(1).Mul(big.NewInt(21000), big.NewInt(1000000000)),
		Gas:       uint64(21000),
		To:        &destinationAccount.Address,
		Value:     transferAmount,
		Data:      nil,
	})

	//signedTx, err := myKeyStore.SignTx(sourceAccount, transaction, chainID)
	//panicIfError(err)

	sourcePrivateKey, err := crypto.HexToECDSA(sourcePrivateKeyString)
	if err != nil {
		log.Fatal(err)
	}
	signedTx, err := types.SignTx(transaction, types.NewEIP155Signer(chainID), sourcePrivateKey)
	panicIfError(err)

	err = client.SendTransaction(context.Background(), signedTx)
	panicIfError(err)

	fmt.Printf("SourceAddress\n")
	logBalancesForAddress(client, sourceAddress)
	fmt.Printf("destinationAddress\n")
	logBalancesForAddress(client, destinationAccount.Address)
}

func panicIfError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func logBalancesForAddress(client *ethclient.Client, toAddress common.Address) {
	balance := getBalance(client, toAddress)
	pendingBalance, err := client.PendingBalanceAt(context.Background(), toAddress)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Account balance for %s was %d wei or %f ether\n", toAddress, balance, weiToEther(balance))
	fmt.Printf("pendingBalance: %d\n", pendingBalance)
}

func getNonceForWalletAddress(client *ethclient.Client, sourceAddress common.Address) uint64 {
	nonce, err := client.PendingNonceAt(context.Background(), sourceAddress)
	if err != nil {
		log.Fatal(err)
	}

	return nonce
}

func getBalance(client *ethclient.Client, address common.Address) *big.Int {
	balance, err := client.BalanceAt(context.Background(), address, nil)
	if err != nil {
		log.Fatal(err)
	}

	return balance
}

func weiToEther(balance *big.Int) *big.Float {
	fbalance := new(big.Float)
	fbalance.SetString(balance.String())
	return new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))
}

func getPublicWalletAddress(privateKey *ecdsa.PrivateKey) string {
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	return address
}
