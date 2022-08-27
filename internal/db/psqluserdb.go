package db

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image/png"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/pquerna/otp/totp"
)

type PsqlUserDb struct {
	Db *pgxpool.Pool
}

func (db *PsqlUserDb) Open(dburl string) {
	var err error
	db.Db, err = pgxpool.Connect(context.Background(), dburl)
	if err != nil {
		DbL.Fatalln(err)
	}

	_, err = db.Db.Exec(context.Background(), `create table if not exists userdb (username text unique,secret text unique,totpimage text unique,password text,token text unique,usertype integer,createdat timestamptz);`)
	if err != nil {
		DbL.Fatalln(err)
	}
}

func (db *PsqlUserDb) Close() {
	db.Db.Close()
}

func (db *PsqlUserDb) Add(Username string, Secret string, TotpImage string, Password string, UserType int) (err error) {
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
	_, err = db.Db.Exec(context.Background(), `insert into userdb (username,secret,totpimage,password,token,usertype,createdat) values ($1,$2,$3,$4,$5,$6,$7);`, Username, Secret, TotpImage, string(bytes), uuid.New().String(), UserType, time.Now())
	return
}

func (db *PsqlUserDb) Delete(username string) (err error) {
	_, err = db.Db.Exec(context.Background(), `delete from userdb where username=$1;`, username)
	return
}

func (db *PsqlUserDb) GetID(username string) (ret int64) {
	ret = -1
	row := db.Db.QueryRow(context.Background(), `select userid from userdb where username=$1;`, username)
	_ = row.Scan(&ret)
	return
}

func (db *PsqlUserDb) UpdatePw(Username string, Password string) (err error) {
	if len(Password) < 5 {
		return fmt.Errorf("username or password size too small")
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(Password), 10)
	if err != nil {
		return
	}
	_, err = db.Db.Exec(context.Background(), `update userdb set password=$1 where username=$2;`, string(bytes), Username)
	return
}

func (db *PsqlUserDb) UpdateOtpSecret(Username string) (err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "exatorrent",
		AccountName: Username,
	})
	if err != nil {
		panic(err)
	}
	Secret := key.Secret()
	_, err = db.Db.Exec(context.Background(), `update userdb set secret=$1 where username=$2;`, string(Secret), Username)
	if err != nil {
		panic(err)
	}
	// convert TOTP to image
	var buf bytes.Buffer
	img, err := key.Image(500, 500)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)
	TotpImage := base64.StdEncoding.EncodeToString(buf.Bytes())
	_, err = db.Db.Exec(context.Background(), `update userdb set totpimage=$1 where username=$2;`, string(TotpImage), Username)
	return
}

func (db *PsqlUserDb) DeleteOtpSecret(Username string) (err error) {
	_, err = db.Db.Exec(context.Background(), `update userdb set secret=$1 where username=$2;`, "", Username)
	if err != nil {
		panic(err)
	}
	_, err = db.Db.Exec(context.Background(), `update userdb set totpimage=$1 where username=$2;`, "", Username)
	return
}

func (db *PsqlUserDb) GetOtpSecret(Username string) (secret string, err error) {
	secret = ""
	row := db.Db.QueryRow(context.Background(), `select secret from userdb where username=$1;`, Username)
	err = row.Scan(&secret)
	if err != nil {
		DbL.Printf("Error reading TOTP secret %s", err)
		DbL.Fatal(err)
	}
	return
}

func (db *PsqlUserDb) GetTotpImage(Username string) (image string, err error) {
	image = ""
	row := db.Db.QueryRow(context.Background(), `select totpimage from userdb where username=$1;`, Username)
	err = row.Scan(&image)
	if err != nil {
		DbL.Printf("Error reading TOTP image %s", err)
		DbL.Fatal(err)
	}
	return
}

func (db *PsqlUserDb) ChangeType(Username string, Type string) (err error) {
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
	_, err = db.Db.Exec(context.Background(), `update userdb set usertype=$1 where username=$2;`, ut, Username)
	return
}

func (db *PsqlUserDb) GetUsers() (ret []*User) {
	ret = make([]*User, 0)

	rows, err := db.Db.Query(context.Background(), `select * from userdb;`)
	if err != nil {
		DbL.Println(err)
	}

	for rows.Next() {
		var user User
		err := rows.Scan(&user.Username, &user.Password, &user.Token, &user.UserType, &user.CreatedAt)
		if err != nil {
			DbL.Println(err)
			return
		}
		ret = append(ret, &user)
	}
	return
}

func (db *PsqlUserDb) IsTotpSet(Username string) (b bool) {
	var totpSecret string
	row := db.Db.QueryRow(context.Background(), `select secret from userdb where username=$1;`, Username)
	err := row.Scan(&totpSecret)
	if err != nil {
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

func (db *PsqlUserDb) Validate(Username string, Password string) (ut int, b bool) {
	var pw string
	row := db.Db.QueryRow(context.Background(), `select usertype,password from userdb where username=$1;`, Username)
	err := row.Scan(&ut, &pw)
	if err != nil {
		return ut, false
	}
	err = bcrypt.CompareHashAndPassword([]byte(pw), []byte(Password))
	return ut, err == nil
}

func (db *PsqlUserDb) SetToken(Username string, Token string) (err error) {
	_, err = db.Db.Exec(context.Background(), `update userdb set token=$1 where username=$2;`, Token, Username)
	return
}

func (db *PsqlUserDb) ValidateToken(Token string) (user string, ut int, err error) {
	if Token == "" {
		return "", -1, fmt.Errorf("token is empty")
	}
	row := db.Db.QueryRow(context.Background(), `select username,usertype from userdb where token=$1;`, Token)
	err = row.Scan(&user, &ut)
	if err != nil {
		return "", -1, err
	}
	return
}
