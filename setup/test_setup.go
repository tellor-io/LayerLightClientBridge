package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

- get latest block height B1
- get validator set at height and respective powers
- write validator set and powers to file
- get Multistore, merkle vals, for block B1, write to file
- submitVal1, get block height B2, get Multistore, merkle vals, for block B2, write to file
- get proof for submitVal1
- submitVal2, get block height B3, get Multistore, merkle vals, for block B3, write to file
- get proof for submitVal2
- foundry test
- load validator set and powers from file
- load Multistore, merkle vals, for block B1, from file
- relay block B1
- relay block B2
- run proof for submitVal1, save value in TestUserContract
- relay block B3
- run proof for submitVal2, save value in TestUserContract

func main() {
	// Replace with your Cosmos chain's API endpoint
	url := "http://localhost:1317/cosmos/base/tendermint/v1beta1/blocks/latest"

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Failed to send request to Cosmos API: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	// Replace with your desired file path
	filePath := "response.json"

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()

	_, err = file.Write(body)
	if err != nil {
		log.Fatalf("Failed to write to file: %v", err)
	}

	log.Printf("Response data written to %s", filePath)
}
