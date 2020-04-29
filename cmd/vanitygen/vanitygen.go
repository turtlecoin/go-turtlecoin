// Copyright 2020 The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

package main

import (
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/turtlecoin/go-turtlecoin/crypto"
	"github.com/turtlecoin/go-turtlecoin/types"
	"github.com/turtlecoin/go-turtlecoin/utils"
)

func main() {
	var pubSpendKey, pubViewKey types.PublicKey
	var privSpendKey types.PrivateKey
	var address string

	if len(os.Args) == 1 {
		println("Please supply a prefix you are looking for")
		return
	}

	prefix := os.Args[1]

	i := 0
	start := time.Now()
	for {
		privSpendKey, pubSpendKey, _ = crypto.GenerateKeys()
		_, pubViewKey = crypto.GenerateViewFromSpend(privSpendKey)
		address = utils.AddressFromKeys(pubSpendKey, pubViewKey)

		if strings.HasPrefix(address[6:], prefix) {
			println("Yay!!! Found an address\nIt took " + strconv.Itoa(i) + " tries\n")
			println("Private Spend Key: " + hex.EncodeToString(privSpendKey[:]))
			println("Address: " + address)
			break
		}

		i++
	}
	stop := time.Now()
	println("\nTook " + stop.Sub(start).String())
}
