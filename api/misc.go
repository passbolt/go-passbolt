package api

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytesRmndr(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func checkAuthTokenFormat(authToken string) error {
	splitAuthToken := strings.Split(authToken, "|")
	if len(splitAuthToken) != 4 {
		return fmt.Errorf("Auth Token Has Wrong amount of Fields")
	}

	if splitAuthToken[0] != splitAuthToken[3] {
		return fmt.Errorf("Auth Token Version Fields Don't match")
	}

	if !strings.HasPrefix(splitAuthToken[0], "gpgauth") {
		return fmt.Errorf("Auth Token Version does not start with 'gpgauth'")
	}

	length, err := strconv.Atoi(splitAuthToken[1])
	if err != nil {
		return fmt.Errorf("Cannot Convert Auth Token Length Field to int: %w", err)
	}

	if len(splitAuthToken[2]) != length {
		return fmt.Errorf("Auth Token Data Length does not Match Length Field")
	}
	return nil
}
