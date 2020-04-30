// Copyright 2020 The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

package main

import (
	"os"
	"strconv"
	"time"

	"github.com/turtlecoin/go-turtlecoin/crypto"
	"github.com/turtlecoin/go-turtlecoin/types"
	"github.com/turtlecoin/go-turtlecoin/utils"
    "github.com/turtlecoin/go-turtlecoin/walletbackend/mnemonics"
)

func genVanityAddress(prefix string, finished chan bool) {
	var pubSpendKey, pubViewKey types.PublicKey
	var privSpendKey types.PrivateKey
	var address string

    endsAt := len(prefix) + 6

	for {
		privSpendKey, pubSpendKey, _ = crypto.GenerateKeys()
		_, pubViewKey = crypto.GenerateViewFromSpend(privSpendKey)
		address = utils.AddressFromKeys(pubSpendKey, pubViewKey)

        if (address[6:endsAt] == prefix) {
            println("Yay, found an address!")
            println("Address: " + address)
            println("\nMnemoic seed:\n\n" + mnemonics.PrivateKeyToMnemonic(privSpendKey))
            break
        }
    }

    finished <- true
}


func main() {

    var err error
    threads := 1

	if len(os.Args) == 1 {
		println("Please supply a prefix you are looking for, and optionally a number of threads to run.")
        println("Example: './vanitygen PRFX 8' would generate the prefix 'PRFX' with 8 concurrent threads.")
        println("Without a threadcount argument, the program will execute with only one thread.")
		return
	}

	prefix := os.Args[1]

    if len(os.Args) > 2 {
        threads, err = strconv.Atoi(os.Args[2])
        if err != nil || threads < 1 || threads > 64 {
            println("Invalid thread count. Must be an integer betweeen 1 and 64.")
            println("If you sincerely need more than that, alter the sourcecode.")
            return
        }
    }

    c := make(chan bool)

	start := time.Now()

    for i := 0; i <= threads; i++ {
        go genVanityAddress(prefix, c)
    }

    <-c
	stop := time.Now()
	println("\nTook " + stop.Sub(start).String())

}
