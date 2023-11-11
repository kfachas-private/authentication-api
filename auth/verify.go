package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"authentication-api/auth/jwt"
	db "authentication-api/database"
)

type ContentVerify struct {
	Token string `json:"token"`
}

// VerifyTokenHandler :
func VerifyTokenHandler(rw http.ResponseWriter, r *http.Request) {
	var p ContentVerify

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&p)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Bad Request"))
		return
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	isValid, err := jwt.ValidateToken(p.Token, jwtSecret)
	fmt.Println(isValid)
	if (err != nil) || (!isValid) {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("Token is invalid"))
		return
	}

	payload, err := jwt.GetPayload(p.Token)
	fmt.Println(payload)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Internal Server Error"))
		return
	}

	// lets see if the user exists
	user, err := db.GetUserById(payload.UserId)

	// this means either the user does not exist
	if (err != nil) || (user == nil) {
		rw.WriteHeader(http.StatusNotFound)
		rw.Write([]byte("User Does not Exist"))
	}

	rw.WriteHeader(http.StatusNoContent)
	rw.Write([]byte("Authorized"))
}
