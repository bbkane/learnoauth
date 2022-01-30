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

func run(pf flag.PassedFlags) error {
	// this is a required flag, so we know it exists
	githubClientID := pf["--client-id"].(string)
	githubClientSecret := pf["--client-secret"].(string)
	port := pf["--port"].(int)

	r := mux.NewRouter()

	oauth2Cfg := &oauth2.Config{
		ClientID:     githubClientID,
		ClientSecret: githubClientSecret,
		Scopes:       []string{},
		Endpoint:     github.Endpoint,
	}

	// auth1: /
	// wtf: /login
	r.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(rw, `<a href="/login/github/">LOGIN</a>`)
	}).Methods("GET")

	// auth1: /login/github/
	// wtf: /oauth/github/
	r.HandleFunc("/login/github/", func(rw http.ResponseWriter, r *http.Request) {
		//

		// Generate new OAuth state for the session to prevent CSRF attacks.
		state := make([]byte, 64)
		if _, err := io.ReadFull(rand.Reader, state); err != nil {
			fmt.Fprintf(rw, "state gen error: %v", err)
			return
		}
		stateHex := hex.EncodeToString(state)

		http.Redirect(
			rw,
			r,
			oauth2Cfg.AuthCodeURL(stateHex),
			http.StatusFound,
		)

	}).Methods("GET")

	// auth1: /login/github/callback/
	// wtf: /oauth/github/callback
	r.HandleFunc("/login/github/callback/", func(rw http.ResponseWriter, r *http.Request) {
		state, code := r.FormValue("state"), r.FormValue("code")

		// TODO: validate that GitHub state matches session state
		fmt.Printf("state: %s", state)

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
	err := srv.ListenAndServe()
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
