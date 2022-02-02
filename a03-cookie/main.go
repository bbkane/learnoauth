package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/bbkane/warg"
	"github.com/bbkane/warg/command"
	"github.com/bbkane/warg/flag"
	"github.com/bbkane/warg/section"
	"github.com/bbkane/warg/value"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func getGithubData(accessToken string) (string, error) {
	// From: https://sharmarajdaksh.github.io/blog/github-oauth-with-go

	// Get request to a set URL
	req, reqerr := http.NewRequest(
		"GET",
		"https://api.github.com/user",
		nil,
	)
	if reqerr != nil {
		return "", fmt.Errorf("API Request creation failed: %w", reqerr)
	}

	// Set the Authorization header before sending the request
	// Authorization: token XXXXXXXXXXXXXXXXXXXXXXXXXXX
	authorizationHeaderValue := fmt.Sprintf("token %s", accessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)

	// Make the request
	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		return "", fmt.Errorf("request failed, %w", resperr)
	}

	// Read the response as a byte slice
	respbody, _ := ioutil.ReadAll(resp.Body)

	// Convert byte slice to string and return
	return string(respbody), nil
}

type User struct {
	Name  string
	Token oauth2.Token
	// State is a random OAuth state
	State string
}

const SessionCookieName = "sessionCookie"

// Session contains per-user information in each request
type Session struct {
	// State is a random string we use to ensure Oauth requests come from our server.
	// See https://www.sohamkamani.com/golang/oauth/#oauth-query-state
	State string `json:"state"`
}

// sessionFromRequest reads the Session information from a request.
// Returns an empty session, error if it runs into an error. When a cookie doesn't exist, returns Session{}, nil
// Unlike most of my functions, it can return an empty Session AND an error at the same time.
// cribbed from wtf (*Server).session
func sessionFromRequest(sc *securecookie.SecureCookie, r *http.Request) (Session, error) {
	// read session from request cookies
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Println("cookie not found")
			return Session{}, nil
		}
		return Session{}, err
	}

	var session Session
	// TODO: how does this work with an empty/non-existent cookie
	err = sc.Decode(SessionCookieName, cookie.Value, &session)
	if err != nil {
		return Session{}, err
	}
	return Session{}, nil
}

// addSessionToResponse saves the Session to a cookie. If there's an error encoding, it doesn't write anything and returns the error
func addSessionToResponse(sc *securecookie.SecureCookie, rw http.ResponseWriter, session Session) error {
	buf, err := sc.Encode(SessionCookieName, session)
	if err != nil {
		return fmt.Errorf("SessionToResponse err: %w", err)
	}
	fmt.Printf("", buf)
	http.SetCookie(
		rw,
		&http.Cookie{
			Name: SessionCookieName,
			// Value:    buf,
			Value:    "mycookie", // TODO: rm
			Path:     "/",
			Expires:  time.Now().Add(30 * 24 * time.Hour),
			Secure:   false, // TODO: change when we start to use TLS
			HttpOnly: true,
		},
	)
	return nil
}

func run(pf flag.PassedFlags) error {
	// this is a required flag, so we know it exists
	blockKeyHex := pf["--block-key"].(string)
	githubClientID := pf["--client-id"].(string)
	githubClientSecret := pf["--client-secret"].(string)
	hasKeyHex := pf["--hash-key"].(string)
	port := pf["--port"].(int)

	r := mux.NewRouter()

	oauth2Cfg := &oauth2.Config{
		ClientID:     githubClientID,
		ClientSecret: githubClientSecret,
		Scopes:       []string{},
		Endpoint:     github.Endpoint,
	}

	// Set up secure cookie management
	// Decode from hex to byte slices.
	hashKey, err := hex.DecodeString(hasKeyHex)
	if err != nil {
		return fmt.Errorf("invalid hash key")
	}
	blockKey, err := hex.DecodeString(blockKeyHex)
	if err != nil {
		return fmt.Errorf("invalid block key")
	}

	// Initialize cookie management & encode our cookie data as JSON.
	sc := securecookie.New(hashKey, blockKey)
	sc.SetSerializer(securecookie.JSONEncoder{})

	// auth1: /
	// wtf: /login
	r.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(rw, `<a href="/login/github/">LOGIN</a>`)
	}).Methods("GET")

	// auth1: /login/github/
	// wtf: /oauth/github/
	r.HandleFunc("/login/github/", func(rw http.ResponseWriter, r *http.Request) {

		// Ignore errors in favor of an empty session if necessary
		// NOTE: WTF *does* check the error case of a bad decode (which should only happen if the cookie is messed with)
		session, _ := sessionFromRequest(sc, r)

		// Generate new OAuth state for the session to prevent CSRF attacks.
		state := make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, state); err != nil {
			fmt.Fprintf(rw, "state gen error: %v", err)
			return
		}

		session.State = hex.EncodeToString(state)

		err := addSessionToResponse(sc, rw, session)
		if err != nil {
			fmt.Fprintf(rw, "session to response err: %v", err)
			return
		}

		http.Redirect(
			rw,
			r,
			oauth2Cfg.AuthCodeURL(session.State),
			http.StatusFound,
		)

	}).Methods("GET")

	// auth1: /login/github/callback/
	// wtf: /oauth/github/callback
	r.HandleFunc("/login/github/callback/", func(rw http.ResponseWriter, r *http.Request) {
		state, code := r.FormValue("state"), r.FormValue("code")

		session, err := sessionFromRequest(sc, r)
		if err != nil {
			fmt.Fprintf(rw, "cannot read state: %v", err)
			return
		}

		if state != session.State {
			fmt.Printf("session: %v\n", session)
			fmt.Printf("form state: %v\n", state)
			fmt.Fprintf(rw, "oauth state mismatch")
			return
		}

		tok, err := oauth2Cfg.Exchange(r.Context(), code)
		if err != nil {
			fmt.Fprintf(rw, "tok exchange err: %v", err)
			return
		}

		data, err := getGithubData(tok.AccessToken)
		if err != nil {
			fmt.Fprintf(rw, "github err: %v", err)
			return
		}
		fmt.Println(data)

	}).Methods("GET")

	// wtf: /logout
	r.HandleFunc("/logout", func(rw http.ResponseWriter, r *http.Request) {

	}).Methods("DELETE")

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	fmt.Printf("Addr: http://%s\n", addr)
	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	err = srv.ListenAndServe()
	if err != nil {
		err = fmt.Errorf("server err: %w", err)
		return err
	}

	return nil
}

func main() {
	app := warg.New(
		"auth2",
		section.New(
			section.HelpShort("Auth2 learning app"),
			section.Command(
				"run",
				command.HelpShort("Run server"),
				run,
				command.Flag(
					"--block-key",
					"Cookie Block Key",
					value.String,
					flag.EnvVars("AUTH_BLOCK_KEY"),
					flag.Required(),
				),
				command.Flag(
					flag.Name("--client-id"),
					flag.HelpShort("GitHub Client ID"),
					value.String,
					flag.EnvVars("AUTH2_GITHUB_CLIENT_ID", "GITHUB_CLIENT_ID"),
					flag.Required(),
				),
				command.Flag(
					flag.Name("--client-secret"),
					flag.HelpShort("GitHub Client Secret"),
					value.String,
					flag.EnvVars("AUTH2_GITHUB_CLIENT_SECRET", "GITHUB_CLIENT_SECRET"),
					flag.Required(),
				),
				command.Flag(
					"--hash-key",
					"Cookie Hash Key",
					value.String,
					flag.EnvVars("AUTH_HASH_KEY"),
					flag.Required(),
				),
				command.Flag(
					"--port",
					"Server port. Should match GitHub app callback URL port",
					value.Int,
					flag.Default("3000"),
					flag.Required(),
				),
			),
		),
	)
	app.MustRun(os.Args, os.LookupEnv)
}
