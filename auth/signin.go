package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"authentication-api/auth/jwt"

	db "authentication-api/database"
)

type User = db.User

// we need this function to be private
func getSignedToken(user *User) (string, error) {
	// we make a JWT Token here with signing method of ES256 and claims.
	// claims are attributes.
	// aud - audience
	// iss - issuer
	// exp - expiration of the Token
	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	// 	"aud": "frontend.knowsearch.ml",
	// 	"iss": "knowsearch.ml",
	// 	"exp": string(time.Now().Add(time.Minute * 1).Unix()),
	// })
	claimsMap := map[string]string{
		"aud":     "frontend.knowsearch.ml",
		"iss":     "knowsearch.ml",
		"user_id": user.Id,
		"role":    strconv.Itoa(user.Role),
		"exp":     fmt.Sprint(time.Now().Add(time.Minute * 1).Unix()),
	}
	// here we provide the shared secret. It should be very complex.\
	// Also, it should be passed as a System Environment variable

	secret := os.Getenv("JWT_SECRET")
	header := "HS256"
	tokenString, err := jwt.GenerateToken(header, claimsMap, secret)
	if err != nil {
		return tokenString, err
	}
	return tokenString, nil
}

type ContentSignin struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SigninHandler : This will be supplied to the MUX router. It will be called when signin request is sent
// if user not found or not validates, returns the Unauthorized error
// if found, returns the JWT back. [How to return this?]
func SigninHandler(rw http.ResponseWriter, r *http.Request) {
	var p ContentSignin

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&p)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Bad Request"))
		return
	}

	// lets see if the user exists
	user, err := db.GetUser(p.Email, p.Password)

	fmt.Println(user)
	// this means either the user does not exist
	if (err != nil) || (user == nil) {
		rw.WriteHeader(http.StatusNotFound)
		rw.Write([]byte("User Does not Exist"))
		return
	}

	tokenString, err := getSignedToken(user)
	if err != nil {
		fmt.Println(err)
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte("Internal Server Error"))
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(tokenString))
}
