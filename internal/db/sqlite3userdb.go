//go:build cgo
// +build cgo

package db

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"

	"github.com/pquerna/otp/totp"
)

type Sqlite3UserDb struct {
	Db *sqlite.Conn
	mu sync.Mutex
}

func (db *Sqlite3UserDb) Open(fp string) {
	var err error
	db.Db, err = sqlite.OpenConn(fp, 0)
	if err != nil {
		DbL.Fatalln(err)
	}

	err = sqlitex.ExecScript(db.Db, `create table if not exists userdb (username text unique,secret text unique,totpimage text unique,password text,token text unique,usertype integer,createdat text);`)

	if err != nil {
		DbL.Fatalln(err)
	}
}

func (db *Sqlite3UserDb) Close() {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.Db.Close()
	if err != nil {
		DbL.Fatalln(err)
	}
}

func (db *Sqlite3UserDb) Add(Username string, Secret string, TotpImage string, Password string, UserType int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("uuid error") // uuid may panic
		}
	}()
	if len(Username) <= 5 || len(Password) <= 5 {
		return fmt.Errorf("username or password size too small")
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(Password), 10)
	if err != nil {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	err = sqlitex.Exec(db.Db, `insert into userdb (username,secret,totpimage,password,token,usertype,createdat) values (?,?,?,?,?,?,?);`, nil, Username, Secret, TotpImage, string(bytes), uuid.New().String(), UserType, time.Now().Format(time.RFC3339))
	return
}

func (db *Sqlite3UserDb) Delete(Username string) (err error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	err = sqlitex.Exec(db.Db, `delete from userdb where username=?;`, nil, Username)
	return
}

func (db *Sqlite3UserDb) UpdatePw(Username string, Password string) (err error) {
	if len(Password) < 5 {
		return fmt.Errorf("username or password size too small")
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(Password), 10)
	if err != nil {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	err = sqlitex.Exec(db.Db, `update userdb set password=? where username=?;`, nil, string(bytes), Username)
	return
}

func (db *Sqlite3UserDb) UpdateOtpSecret(Username string) (err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "exatorrent",
		AccountName: Username,
	})
	if err != nil {
		panic(err)
	}
	Secret := key.Secret()
	// convert TOTP to image
	var buf bytes.Buffer
	img, err := key.Image(500, 500)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)
	TotpImage := base64.StdEncoding.EncodeToString(buf.Bytes())
	db.mu.Lock()
	defer db.mu.Unlock()
	err = sqlitex.Exec(db.Db, `update userdb set secret=? where username=?;`, nil, string(Secret), Username)
	if err != nil {
		panic(err)
	}
	DbL.Printf("Image is : %s", TotpImage)
	err = sqlitex.Exec(db.Db, `update userdb set totpimage=? where username=?;`, nil, string(TotpImage), Username)
	return
}
func (db *Sqlite3UserDb) DeleteOtpSecret(Username string) (err error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	err = sqlitex.Exec(db.Db, `update userdb set secret=? where username=?;`, nil, "", Username)
	if err != nil {
		panic(err)
	}
	err = sqlitex.Exec(db.Db, `update userdb set totpimage=? where username=?;`, nil, "", Username)
	return
}

func (db *Sqlite3UserDb) GetOtpSecret(Username string) (secret string, err error) {
	var exists bool
	var serr error
	db.mu.Lock()
	defer db.mu.Unlock()
	serr = sqlitex.Exec(
		db.Db, `select secret from userdb where username=?;`,
		func(stmt *sqlite.Stmt) error {
			exists = true
			secret = stmt.GetText("secret")
			return nil
		}, Username)
	if serr != nil {
		DbL.Printf("Error reading TOTP secret %s", serr)
		return "", serr
	}
	if !exists {
		DbL.Printf("Error reading TOTP secret. User not exist. %s", serr)
		return "", serr
	}
	return
}
func (db *Sqlite3UserDb) GetTotpImage(Username string) (image string, err error) {
	var exists bool
	var serr error
	db.mu.Lock()
	defer db.mu.Unlock()
	serr = sqlitex.Exec(
		db.Db, `select totpimage from userdb where username=?;`,
		func(stmt *sqlite.Stmt) error {
			exists = true
			image = stmt.GetText("totpimage")
			return nil
		}, Username)
	if serr != nil {
		DbL.Printf("Error reading TOTP image %s", serr)
		return "", serr
	}
	if !exists {
		DbL.Printf("Error reading TOTP image. User not exist. %s", serr)
		return "", serr
	}
	return
}

func (db *Sqlite3UserDb) ChangeType(Username string, Type string) (err error) {
	if len(Username) == 0 {
		return fmt.Errorf("empty username")
	}
	var ut int
	if Type == "admin" {
		ut = 1
	} else if Type == "user" {
		ut = 0
	} else if Type == "disabled" {
		ut = -1
	} else {
		return fmt.Errorf("unknown type")
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	err = sqlitex.Exec(db.Db, `update userdb set usertype=? where username=?;`, nil, ut, Username)
	return
}

func (db *Sqlite3UserDb) GetUsers() (ret []*User) {
	ret = make([]*User, 0)
	var terr error

	db.mu.Lock()
	defer db.mu.Unlock()
	_ = sqlitex.Exec(
		db.Db, `select * from userdb;`,
		func(stmt *sqlite.Stmt) error {
			var user User
			user.Username = stmt.GetText("username")
			user.Password = stmt.GetText("password")
			user.Token = stmt.GetText("token")
			user.UserType = stmt.ColumnInt(3)
			user.CreatedAt, terr = time.Parse(time.RFC3339, stmt.GetText("createdat"))
			if terr != nil {
				DbL.Println(terr)
				return terr
			}
			ret = append(ret, &user)
			return nil
		})
	return
}

func (db *Sqlite3UserDb) IsTotpSet(Username string) (ret bool) {
	var exists bool
	var serr error
	var totpSecret string
	db.mu.Lock()
	defer db.mu.Unlock()
	serr = sqlitex.Exec(
		db.Db, `select secret from userdb where username=?;`,
		func(stmt *sqlite.Stmt) error {
			exists = true
			totpSecret = stmt.GetText("secret")
			return nil
		}, Username)

	if serr != nil {
		return false
	}
	if !exists {
		return false
	}
	if totpSecret == "" {
		DbL.Printf("Totp status is %t for user %s", false, Username)
		return false
	} else {
		DbL.Printf("Totp status is %t for user %s", true, Username)
		return true
	}
}

func (db *Sqlite3UserDb) Validate(Username string, Password string) (ut int, ret bool) {
	var pw string
	var exists bool
	var serr error

	db.mu.Lock()
	defer db.mu.Unlock()
	serr = sqlitex.Exec(
		db.Db, `select usertype,password from userdb where username=?;`,
		func(stmt *sqlite.Stmt) error {
			exists = true
			ut = stmt.ColumnInt(0)
			pw = stmt.GetText("password")
			return nil
		}, Username)

	if serr != nil {
		return -1, false
	}
	if !exists {
		return -1, false
	}

	serr = bcrypt.CompareHashAndPassword([]byte(pw), []byte(Password))
	return ut, serr == nil
}

func (db *Sqlite3UserDb) ValidateToken(Token string) (user string, ut int, err error) {
	if Token == "" {
		return "", -1, fmt.Errorf("token is empty")
	}
	var exists bool
	db.mu.Lock()
	defer db.mu.Unlock()
	err = sqlitex.Exec(
		db.Db, `select usertype,username from userdb where token=?;`,
		func(stmt *sqlite.Stmt) error {
			exists = true
			ut = stmt.ColumnInt(0)
			user = stmt.GetText("username")
			return nil
		}, Token)

	if err != nil {
		return "", -1, err
	}
	if !exists {
		return "", -1, fmt.Errorf("token doesn't exist")
	}
	if user == "" {
		return "", -1, fmt.Errorf("user doesn't exist")
	}
	return
}

func (db *Sqlite3UserDb) SetToken(Username string, Token string) (err error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	err = sqlitex.Exec(db.Db, `update userdb set token=? where username=?;`, nil, Token, Username)
	return
}
