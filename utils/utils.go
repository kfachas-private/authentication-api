package utils

import "regexp"

// IsEmailValid checks if the email provided is valid or not
func IsEmailValid(e string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(e)
}

// CheckError is a helper function to panic in case of error
func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}
