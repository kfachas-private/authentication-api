package models

import (
	"database/sql"
)

type User struct {
	Id           string         `json:"id"`
	Email        sql.NullString `json:"email"`
	Username     sql.NullString `json:"username"`
	PasswordHash string         `json:"password_hash"`
	Role         int            `json:"role"`
	CreatedDate  string         `json:"created_date"`
}
