package main

import (
	"encoding/hex"
	"fmt"

	"github.com/0xstepit/signatures-verification/crypto"
)

const (
	COSMOS_COIN_TYPE   = 118
	ETHEREUM_COIN_TYPE = 60
)

func main() {
	mnemonic := crypto.GenerateMnemonic(true)
	fmt.Println("Mnemonic: ", mnemonic)

	// Use the mnemonic to generate a private key using BIP32 and BIP44
	// with Interchain coin_type.
	privKey, pubKey := crypto.DeriveKeys(mnemonic, COSMOS_COIN_TYPE, 0)
	pubKeyHex := hex.EncodeToString(pubKey.SerializeCompressed())
	// Generate address using Cosmos SDK algorithm.
	address := crypto.DeriveCosmosAddress(pubKey)
	addressHex := hex.EncodeToString(address)
	addressBech32 := crypto.ConvertToBech32(address, "cosmos")

	fmt.Println("\nCOSMOS")
	fmt.Println("-----------------------------------------------------------------------------------")
	fmt.Println("Coin type 118")
	fmt.Println("Address Cosmos")
	fmt.Println("PrivKey hex:    ", privKey.Key.String())
	fmt.Println("PubKey hex:     ", pubKeyHex)
	fmt.Println("Address hex:    ", addressHex)
	fmt.Println("Address bech32: ", addressBech32)

	// Use the mnemonic to generate a private key using BIP32 and BIP44
	// with Ethereum coin_type.
	privKey, pubKey = crypto.DeriveKeys(mnemonic, ETHEREUM_COIN_TYPE, 0)
	pubKeyHex = hex.EncodeToString(pubKey.SerializeCompressed())
	// Generate address using Ethereum algorithm.
	addressEthereum := crypto.DeriveEthereumAddress(pubKey)
	// Generate address using Cosmos SDK algorithm.
	addressHex = hex.EncodeToString(addressEthereum)
	addressBech32 = crypto.ConvertToBech32(addressEthereum, "evmos")
	fmt.Println("\nEVMOS")
	fmt.Println("-----------------------------------------------------------------------------------")
	fmt.Println("Coin type 60")
	fmt.Println("Address Ethereum")
	fmt.Println("PrivKey hex:    ", privKey.Key.String())
	fmt.Println("PubKey hex:     ", pubKeyHex)
	fmt.Println("Address hex     ", addressHex)
	fmt.Println("Address bech32: ", addressBech32)

	fmt.Println("\n COSMOS VARIANTS")
	fmt.Println("-----------------------------------------------------------------------------------")
	addressBech32 = crypto.ConvertToBech32(addressEthereum, "cosmos")
	fmt.Println("Ethereum address bech32:              ", addressBech32)
	addressCosmos := crypto.DeriveCosmosAddress(pubKey)
	addressBech32 = crypto.ConvertToBech32(addressCosmos, "cosmos")
	fmt.Println("Cosmos coin type 60 address bech32:   ", addressBech32)
}
