package main

import (
	"fmt"
	"log"
	"net/http"

	"authentication-api/auth/middleware"
	gohandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"authentication-api/auth"
	db "authentication-api/database"
)

func main() {
	fmt.Println("Server started")

	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	db.DbInit()
	defer db.DbClose()

	mainRouter := mux.NewRouter()
	// We will create a Subrouter for Authentication service
	// route for sign up and signin. The Function will come from auth-service package
	// checks if given header params already exists. If not,it adds the user
	mainRouter.HandleFunc("/signup", auth.SignupHandler).Methods("POST")
	mainRouter.HandleFunc("/signin", auth.SigninHandler).Methods("POST")
	mainRouter.HandleFunc("/verify", auth.VerifyTokenHandler).Methods("GET")

	// Add the Middleware for all routes
	mainRouter.Use(middleware.BasicAuthMiddleware)

	// CORS Header
	ch := gohandlers.CORS(gohandlers.AllowedOrigins([]string{"http://localhost:3000"}))

	// HTTP Server
	// Add Time outs
	server := &http.Server{
		Addr:    "127.0.0.1:9090",
		Handler: ch(mainRouter),
	}
	err = server.ListenAndServe()

	if err != nil {
		fmt.Println("Error Booting the Server")
	}
}
