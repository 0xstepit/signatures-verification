package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"log"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

const (
	MNEOMONIC = "copper push brief egg scan entry inform record adjust fossil boss egg comic alien upon aspect dry avoid interest fury window hint race symptom"
)

// GenerateMnemonic generates a mnemonic from 256 bit of enrtopy or use the hardcoded value
// if true passed as input. The function uses BIP39.
func GenerateMnemonic(hardcoded bool) string {
	if hardcoded {
		return MNEOMONIC
	}

	// Create 256 bits of entropy.
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Fatal(err)
	}

	// Generate mnemonic following BIP39.
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatal(err)
	}
	return mnemonic
}

// DeriveKeys is used to generate a private and a public key using BIP32 and BIP 44.
func DeriveKeys(mnemonic string, coin_type, address_index uint32) (btcec.PrivateKey, btcec.PublicKey) {
	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}
	path := []uint32{44 + bip32.FirstHardenedChild, coin_type + bip32.FirstHardenedChild, bip32.FirstHardenedChild, 0, address_index}
	key := masterKey
	for _, index := range path {
		key, err = key.NewChildKey(index)
		if err != nil {
			log.Fatal(err)
		}
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(key.Key)
	return *privKey, *pubKey
}

// DeriveCosmosAddress is used to generate a Cosmos SDK address starting from
// a public key.
func DeriveCosmosAddress(pubKey btcec.PublicKey) []byte {
	pubKeyBytes := pubKey.SerializeCompressed()
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(pubKeyHash[:])
	return ripemd160Hasher.Sum(nil)[:20]
}

// ConvertToBech32 is used to encode an hex representation of an address
// into a bech32 representation.
func ConvertToBech32(address []byte, hrp string) string {
	converted, err := bech32.ConvertBits(address, 8, 5, true)
	if err != nil {
		log.Fatal(err)
	}

	addressBech32, err := bech32.Encode(hrp, converted)
	if err != nil {
		log.Fatal(err)
	}
	return addressBech32
}

// DeriveEthereumAddress is used to generate an Ethereum address starting from
// a public key.
func DeriveEthereumAddress(pubKey btcec.PublicKey) []byte {
	pubKeyBytes := pubKey.SerializeUncompressed()
	keccak := sha3.NewLegacyKeccak256()
	keccak.Write(pubKeyBytes[1:])
	return keccak.Sum(nil)[12:]
}
