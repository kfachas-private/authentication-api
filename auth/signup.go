package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	db "authentication-api/database"
)

type ContentSignup struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignupHandler adds the user to the database of users
func SignupHandler(rw http.ResponseWriter, r *http.Request) {
	headerContentTtype := r.Header.Get("Content-Type")
	if headerContentTtype != "application/json" {
		errorResponse(rw, "Content Type is not application/json", http.StatusUnsupportedMediaType)
		return
	}

	var p ContentSignup

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&p)

	if err != nil {
		fmt.Println(err)
		errorResponse(rw, "Error parsing the request body", http.StatusBadRequest)
		return
	}

	// validate and then add the user
	db.CreateUser(p.Email, p.Password)

	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("User Created"))
}

func errorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	w.Write([]byte(message))
}
