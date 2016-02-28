package main

import (
	"fmt"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		helpMessage()
		return
	}

	if os.Args[1] == "help" {
		helpMessage()
		return
	}

	getDomainHistory(os.Args[1])
	return
}

func getDomainHistory(domainName string) {
	/*
		This is a little hackish but it gets the domain history from SANS using HTTPS which presently I couldn't find in their APIs.

		Gets a client, retrieves a valid token, then cuts up the response in managable chunks. If nothing comes back, give an all clear.
	*/
	token := ""

	// create a cookie jar to hook on to client
	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(&options)
	if err != nil {
		log.Fatal(err)
	}

	//create an http client
	client := http.Client{Jar: jar}
	resp, err := client.Get("https://isc.sans.edu/suspicious_domains.html")
	if err != nil {
		log.Fatal(err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	// get token
	dataResp := string(data)
	pos := strings.Index(dataResp, `<input type="hidden" name="token" value="`)
	lengthOfStr := len(`<input type="hidden" name="token" value="`)
	pos += lengthOfStr - 1
	dataResp = dataResp[pos:]
	pos = strings.Index(dataResp, `" />`)
	dataResp = dataResp[1:pos]
	token = dataResp

	urlData := url.Values{}
	urlData.Set("token", token)
	urlData.Set("submit", "Search History")
	urlData.Set("domainhistory", domainName)

	resp, err = client.PostForm("https://isc.sans.edu/suspicious_domains.html#search", urlData)

	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}

	dataResp = string(data)

	//trim down to something manageable
	pos = strings.Index(dataResp, `<h4>Search for domain history and details:</h4>`)
	lengthOfStr = len(`<h4>Search for domain history and details:</h4>`)
	pos += lengthOfStr - 1
	dataResp = dataResp[pos:]
	pos = strings.Index(dataResp, `<h4>Creates a custom domain list file</h4>`)
	dataResp = dataResp[1:pos]

	//once more
	dataResp, _ = cutHTMLEntity(dataResp, "blockquote")

	//now get all the strong tags
	caption, dataResp := cutHTMLEntity(dataResp, "strong")
	value := ""
	foundSomething := false
	for strings.Trim(caption, " ") != "" {
		value, dataResp = cutToHTMLEntity(dataResp, "br /")
		s := strings.Trim(bold(cleanHTMLEntity(caption))+cleanHTMLEntity(value), " ")
		if s != "" {
			foundSomething = true
		}
		fmt.Print(s + "\n")

		caption, dataResp = cutHTMLEntity(dataResp, "strong")
	}
	if foundSomething {
		fmt.Println(string(dataResp))
		fmt.Println(bold("CAUTION:") + " This domain has a suspicious domain entry. If there are no Whitelist Detail, you might want to avoid links or emails from this site.")
	} else {
		fmt.Println("This domain has no suspicious domain entry, yet. Try other iterations, thoough, just to be sure.")
	}

	return
}

func cutHTMLEntity(sourceHTML, tagName string) (string, string) {
	// return the value within the tags

	pos := strings.Index(sourceHTML, `<`+tagName+`>`)
	if pos == -1 {
		return "", sourceHTML
	}
	lengthOfStr := len(`<` + tagName + `>`)
	pos += lengthOfStr - 1
	sourceHTML = sourceHTML[pos:]
	pos = strings.Index(sourceHTML, `</`+tagName+`>`)
	return sourceHTML[1:pos], sourceHTML[pos+lengthOfStr+1:]
}

func cutToHTMLEntity(sourceHTML, tagName string) (string, string) {
	// return the value up to the tag

	pos := strings.Index(sourceHTML, `<`+tagName+`>`)
	if pos == -1 {
		return "", sourceHTML
	}
	lengthOfStr := len(`<` + tagName + `>`)
	return sourceHTML[1:pos], sourceHTML[pos+lengthOfStr:]
}

func cleanHTMLEntity(sourceHTML string) string {
	// return the first string with the tag removed
	r := regexp.MustCompile(`\<(\S*)[\s|\S]*\>(.*)\<(\S*)\>`)
	m := r.FindStringSubmatch(sourceHTML)
	if len(m) == 0 {
		return sourceHTML
	}
	if m[2] == "" {
		return m[0]
	}
	return m[2]
}

func helpMessage() {
	// print the help message

	fmt.Println(bold("USAGE:"))
	fmt.Println(bold("rub domainname") + " - returns whether the domain is suspicious")
	fmt.Println("Uses info from Internet Storm Center https://isc.sans.edu")
	fmt.Println("(for more info lonnie@lonniewebb.com)")
}

func bold(str string) string {
	// return bold text
	if strings.Trim(str, " ") != "" {
		return "\033[1m" + str + "\033[0m"
	}
	return ""
}
