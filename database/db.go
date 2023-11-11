package database

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"authentication-api/database/models"
	"authentication-api/utils"
)

type User = models.User

// table Users
const (
	createUserTable = `CREATE TABLE IF NOT EXISTS users (
    		id SERIAL PRIMARY KEY UNIQUE,
    		email TEXT NULL UNIQUE,
    		username TEXT NULL UNIQUE,
    		password_hash TEXT NOT NULL UNIQUE,
    		role INT NOT NULL,
    		created_date TEXT NOT NULL
                                 		);`
)

var db *sql.DB

// DbInit This function will make a connection to the database only once.
func DbInit() {
	var err error

	dbUrl := os.Getenv("DATABASE_URL")
	db, err = sql.Open("postgres", dbUrl)

	if err = db.Ping(); err != nil {
		panic(err)
	}

	_, err = db.Exec(createUserTable)
	utils.CheckError(err)

	// this will be printed in the terminal, confirming the connection to the database
	fmt.Println("The database is connected")
}

func DbClose() {
	fmt.Println("there")
	defer db.Close()
}

// CreateUser This function will create a new user in the database
func CreateUser(email, password string) {
	// Logic for creating a new user

	passwordHash, err := HashPassword(password)
	utils.CheckError(err)

	// dynamic
	insertDynStmt := `insert into "users"("email", "password_hash", "role", "created_date") values($1, $2, $3, $4)`
	_, err = db.Exec(insertDynStmt, email, passwordHash, 0, "2020-01-01")
	utils.CheckError(err)
}

func ScanUserRow(row *sql.Row) (User, error) {
	var u User
	err := row.Scan(
		&u.Id,
		&u.Email,
		&u.Username,
		&u.PasswordHash,
		&u.Role,
		&u.CreatedDate)
	if err != nil {
		return User{}, err
	}
	return u, nil
}
func ScanUserRows(rows *sql.Rows) ([]User, error) {
	var u User
	var users []User
	for rows.Next() {
		err := rows.Scan(
			&u.Id,
			&u.Email,
			&u.Username,
			&u.PasswordHash,
			&u.CreatedDate,
			&u.Role)
		if err != nil {
			return []User{}, err
		}
		users = append(users, u)
	}

	return []User{u}, nil
}

// GetUser This function will get a user from the database
func GetUser(email string, password string) (*User, error) {
	// Logic for getting a user

	// this calls sql.Open, etc.
	// note the below syntax only works for postgres
	row := db.QueryRow("SELECT * FROM users WHERE email = $1", email)

	user, err := ScanUserRow(row)
	if err != nil {
		fmt.Println("User not found")
		fmt.Println(err)
		return nil, err
	}

	if !CheckPasswordHash(password, user.PasswordHash) {
		fmt.Println("Incorrect password")
		return nil, fmt.Errorf("Incorrect password")
	}

	fmt.Println("User found")
	return &user, nil
}

func GetUserById(id string) (*User, error) {
	// Logic for getting a user

	// this calls sql.Open, etc.
	// note the below syntax only works for postgres
	row := db.QueryRow("SELECT * FROM users WHERE id = $1", id)

	user, err := ScanUserRow(row)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func UpdateUser(username, password string) {
	// Logic for updating an existing user

	// update
	updateStmt := `update "users" set "Name"=$1, "Roll_Number"=$2 where "id"=$3`
	_, err := db.Exec(updateStmt, "Rachel", 24, 8)
	utils.CheckError(err)
}

func DeleteUser(username string) {
	// Logic for deleting a user

	// Delete
	deleteStmt := `delete from "users" where id=$1`
	_, err := db.Exec(deleteStmt, 1)
	utils.CheckError(err)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
