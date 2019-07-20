package main

import (
	"github.com/levigross/grequests"
	"log"
	"os"
)

var GITHUB_TOKEN = os.Getenv("GITHUB_TOKEN")
var requestOptions = &grequests.RequestOptions{Auth: []string{GITHUB_TOKEN, "x-oauth-basic"}}

type Repo struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"fullName"`
	Fork     int    `json:"fork"`
	Private  bool   `json:"private"`
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

func main() {
	checkTokenEmpty()
	var repos []Repo
	reposUrl := "https://api.github.com/users/torvalds/repos"
	resp := getStats(reposUrl)
	resp.JSON(&repos)
	log.Println(repos)
}
