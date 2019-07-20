package main

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gorilla/mux"
	"github.com/levigross/grequests"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// see https://www.grc.com/passwords.htm
// long and 64 random hexadecimal characters (0-9 and A-F)
var secretKey = []byte("95AE6D11EAFF5225119764151EBEB23D117BFFD4EB578EDAF70F03098BD5F79F")
var users = map[string]string{"seoy": "father", "haein": "daughter"}

var GITHUB_TOKEN = os.Getenv("GITHUB_TOKEN")

var requestOptions = &grequests.RequestOptions{
	Auth: []string{GITHUB_TOKEN, "x-oauth-basic"}}

type Response struct {
	Token  string `json:"token"`
	Status string `json:"status"`
}

type Repo struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"fullName"`
	Fork     int    `json:"fork"`
	Private  bool   `json:"private"`
}

type File struct {
	Content string `json :"content"`
}

type Gist struct {
	Description string          `json:"description"`
	Public      bool            `json:"public"`
	Files       map[string]File `json:"files"`
}

func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	tokenString, err := request.HeaderExtractor{
		"access_token"}.ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method:%v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access Denied: Please check the access token"))
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		response := make(map[string]string)
		response["user"] = claims["username"].(string)
		response["time"] = time.Now().String()
		responseJson, _ := json.Marshal(response)
		w.Write(responseJson)
	} else {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(err.Error()))
	}
}

func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	/*err := r.ParseForm()
	if err != nil {
		http.Error(w, "Please pass the data as URL form encoded", http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")*/

	//TODO : 19-07-20 password should be crpyto and then will be matched
	// bcrypt.CompareHashAndPassWord(password,[]byte(expectPassword))
	// see https://github.com/golang/crypto/blob/master/bcrypt/bcrypt.go#L99
	username := string("seoy")
	password := string("father")

	if originalPassword, ok := users[username]; ok {
		if password == originalPassword {
			// Create a claims map
			claims := jwt.MapClaims{
				"username":  username,
				"ExpiresAt": 15000,
				"IssuedAt":  time.Now().Unix(),
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(secretKey)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte(err.Error()))
			}
			response := Response{Token: tokenString, Status: "success"}
			responseJSON, _ := json.Marshal(response)
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(responseJSON)

		} else {
			http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
			return
		}
	} else {
		http.Error(w, "User is not found", http.StatusNotFound)
		return
	}

}
func createGist(url string, args []string) *grequests.Response {
	description := args[0]
	var fileContents = make(map[string]File)

	for i := 1; i < len(args); i++ {
		dat, err := ioutil.ReadFile(args[i])
		if err != nil {
			log.Println("please check the filenames. Absolute path or same directory are allowed")
			return nil
		}
		var file File
		file.Content = string(dat)
		fileContents[args[i]] = file
	}
	var gist = Gist{Description: description, Public: true, Files: fileContents}
	var postBody, _ = json.Marshal(gist)
	var requestOptionCopy = requestOptions
	requestOptionCopy.JSON = string(postBody)

	resp, err := grequests.Post(url, requestOptionCopy)
	if err != nil {
		log.Println("Create request failed for Github API")
	}
	return resp
}

func checkTokenEmpty() {
	token := GITHUB_TOKEN
	if len(token) == 0 {
		log.Fatalln("GITHUB TOKEN is empty")
		return
	}
}

func getStats(url string) *grequests.Response {
	resp, err := grequests.Get(url, requestOptions)

	if err != nil {
		log.Fatalln("unable to make request:", err)
	}
	return resp
}

//TODO : 19-07-20 commands and its arguments should be set til 26 at least by seoy.
func main() {
	checkTokenEmpty()
	app := cli.NewApp()
	app.Commands = []cli.Command{
		{
			Name:    "fetch",
			Aliases: []string{"f"},
			Usage:   "Fetch the repo details with user. [Usage]:goTool fetch user",
			Action: func(c *cli.Context) error {
				if c.NArg() > 0 {
					log.Println(c.NArg())
					var repos []Repo
					user := c.Args()[0]
					var repoUrl = fmt.Sprintf("https://api.github.com/users/%s/repos", user)
					resp := getStats(repoUrl)
					resp.JSON(&repos)
					log.Println(repos)
				} else {
					log.Println("Please give a username. see -h to see help")
				}
				return nil
			},
		},
		{
			Name:    "create",
			Aliases: []string{"c"},
			Usage:   "Create a gist from the given text. [Usage]:goTool Nme 'description' sample.text",
			Action: func(c *cli.Context) error {
				if c.NArg() > 1 {
					args := c.Args()
					var postUrl = "https://api.github.com/gists"
					resp := createGist(postUrl, args)
					log.Println(resp.String())
				} else {
					log.Println("Please give sufficient arguments. See -h to see help")
				}
				return nil
			},
		},
	}
	app.Version = "1.0"
	app.Run(os.Args)
	/*var repos []Repo
	reposUrl := "https://api.github.com/users/seoyhaein/repos"
	resp := getStats(reposUrl)
	resp.JSON(&repos)
	log.Println(repos)*/

	r := mux.NewRouter()
	r.HandleFunc("/getToken", getTokenHandler)
	r.HandleFunc("/healthcheck", HealthcheckHandler)
	http.Handle("/", r)

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8000",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
