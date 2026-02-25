package api

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var isUUID = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

func checkAuthTokenFormat(authToken string) error {
	splitAuthToken := strings.Split(authToken, "|")
	if len(splitAuthToken) != 4 {
		return fmt.Errorf("auth Token Has Wrong amount of Fields")
	}

	if splitAuthToken[0] != splitAuthToken[3] {
		return fmt.Errorf("auth Token Version Fields Don't match")
	}

	if !strings.HasPrefix(splitAuthToken[0], "gpgauth") {
		return fmt.Errorf("auth Token Version does not start with 'gpgauth'")
	}

	length, err := strconv.Atoi(splitAuthToken[1])
	if err != nil {
		return fmt.Errorf("cannot Convert Auth Token Length Field to int: %w", err)
	}

	if len(splitAuthToken[2]) != length {
		return fmt.Errorf("auth Token Data Length does not Match Length Field")
	}
	return nil
}

func checkUUIDFormat(data string) error {
	if !isUUID.MatchString(data) {
		return fmt.Errorf("uUID is not in the valid format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}
	return nil
}
