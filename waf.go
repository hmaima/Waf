package waf

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/kitabisa/teler-waf"
	"github.com/kitabisa/teler-waf/request"
	"github.com/kitabisa/teler-waf/threat"
	// /"github.com/govwa/user/session"
)

// convert httprouter.Handle to http.HandlerFunc
func ConvertToHandlerFunc(h httprouter.Handle) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := httprouter.ParamsFromContext(r.Context())
		h(w, r, params)
	}
}

// Convert http.Handler to httprouter.Handle
func ConvertToHttprouterHandle(h http.Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
		h.ServeHTTP(w, r)
	}
}

var TelerWAF = teler.New(teler.Options{
	Excludes: []threat.Threat{
		threat.BadReferrer,
		threat.BadCrawler,
	},

	Whitelists:      []string{
		//`request.IP in ["127.0.0.1", "::1", "0.0.0.0"]`,
	},
	CustomsFromFile: "",
	Customs: []teler.Rule{
		{
			Name:      "SQL Injection",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?i)\b(?:select|union|insert|update|delete|drop|exec)\b`,
				},
			},
		},
		{
			Name:      "Cross site scripting ",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?i)<script[^>]*>.*<\/script>`,
				},
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?i)\b(document\.[a-zA-Z]+|window\.[a-zA-Z]+)\b`,
				},
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `<[^>]*>`,
				},
			},
		},
		
		
		

		{
			Name:      "Detects url-, name-, JSON, and referrer-contained payload attacks",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:[+\\/]\s*name[\W\d]*[)+])|(?:;\W*url\s*=)|(?:[^\w\s\/?:>]\s*(?:location|referrer|name)\s*[^\\/\w\s-])`,
				},
			},
		},

	

		{
			Name:      "Detects self contained xss via with(), common loops and regex to string conversion",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:with\s*\\(\s*.+\s*\\)\s*\w+\s*\\())|(?:(?:do|while|for)\s*\\([^)]*\\)\s*\\{)|(?:\/[\w\s]*\\[\W*\w])`,
				},
			},
		},

		
	},
	LogFile: "teler.log",
})

var rejectHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// This is the handler function for the route that we want to be rejected
	// if the teler-waf's security measures are triggered.
	http.Error(w, "Sorry, your request has been denied for security reasons.", http.StatusForbidden)
})

func main() {

	TelerWAF.SetHandler(rejectHandler)

}
