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

	Whitelists:      []string{},
	CustomsFromFile: "",
	Customs: []teler.Rule{
		/*{
			Name:      "SQL Injection",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?i)\b(?:select|union|insert|update|delete|drop|exec)\b`,
				},
			},
		},*/
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
			Name:      "finds html breaking injections including whitespace attacks",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\"[^\"]*[^-]?>)|(?:[^\\w\\s]\\s*\\/>)|(?:>\")`,
				},
			},
		},

		{
			Name:      "finds attribute breaking injections including whitespace attacks",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:"+.*[<=]\s*"[^"]+")|(?:"\s*\w+\s*=)|(?:>\w=\/)|(?:#.+\)["\s]*>)|(?:"\s*(?:src|style|on\w+)\s*=\s*")|(?:[^"\\]+?"[,;\s]+\w*[\\[\\(])`,
				},
			},
		},

		{
			Name:      "finds unquoted attribute breaking injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:^>[\w\s]*<\\/?\w{2,}>)`,
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

		/*{
			Name:      "Detects hash-contained xss payload attacks, setter usage and property overloading",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\W\s*hash\s*[^\w\s-])|(?:\w+=\W*[^,]*,[^\s(]\s*\()|(?:\?\"[^\s\"]\":)|(?:(?<!\/)__[a-z]+__)|(?:(?:^|[\s)\]\}])(?:s|g)etter\s*=)`,
				},
			},
		},*/

		/*{
			Name:      "Detects self contained xss via with(), common loops and regex to string conversion",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:with\s*\\(\s*.+\s*\\)\s*\w+\s*\\())|(?:(?:do|while|for)\s*\\([^)]*\\)\s*\\{)|(?:\/[\w\s]*\\[\W*\w])`,
				},
			},
		},*/

		/*{
			Name:      "Detects JavaScript with(), ternary operators and XML predicate attacks",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:[=(].+\?.+:)|(?:with\([^)]*\))|(?:(?<!\.)\s*source\W)`,
				},
			},
		},*/
		/*{
			Name:      "Detects self-executing JavaScript functions",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\/\w*\s*\)\s*\()|(?:\([\w\s]+\([\w\s]+\)[\w\s]+\))|(?:(?<!\/(?:mozilla\/\d\.\d\s))\([^)\[]+\[[^\]]+\][^)]*\))|(?:[^\s!][{([][^({[]+[{([][^}\\])]+[}\\])][\s+",\d]*[}\\])])|(?:"\)?\]\W*\[)|(?:=\s*[^:;]+\s*[{([][^}\\])]+[}\\])];)`,
				},
			},
		},*/
		/*{
			Name:      "Detects the IE octal, hex and unicode entities",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?i)(?:\\\\u(?:\\{(0{1,})?[a-f0-9]{2}\\}|00[a-f0-9]{2}))|(?:\\\\x0*[a-f0-9]{2})|(?:\\\\\\d{2,3})`,
				},
			},
		},
		{
			Name:      "Detects basic directory traversal",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:(?:\\/|\\\\)?\\.+(\\/|\\\\)(?:\\.+)?)|(?:\\w+\\.exe\\??\\s)|(?:;\\s*\\w+\\s*\\/[\\w*-]+\\/)|(?:\\d\\.\\dx\\|)|(?:%(?:c0\\.|af\\.|5c\\.))|(?:\\/(?:%2e){2})`,
				},
			},
		},
		{
			Name:      "Detects specific directory and path traversal",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:%c0%ae\\/)|(?:(?:\\/|\\\\)(home|conf|usr|etc|proc|opt|s?bin|local|dev|tmp|kern|[br]oot|sys|system|windows|winnt|program|%[a-z_-]{3,}%)(?:\\/|\\\\))|(?:(?:\\/|\\\\)inetpub|localstart\\.asp|boot\\.ini)`,
				},
			},
		},
		{
			Name:      "Detects etc/passwd inclusion attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:etc\\/\\W*passwd)`,
				},
			},
		},
		{
			Name:      "Detects halfwidth/fullwidth encoded unicode HTML breaking attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:%u(?:ff|00|e\\d)\\w\\w)|(?:(?:%(?:e\\w|c[^3\\W]|))(?:%\\w\\w)(?:%\\w\\w)?)`,
				},
			},
		},
		{
			Name:      "Detects possible includes, VBSCript/JScript encoded and packed functions",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:#@~\\^\\w+)|(?:\\w+script:|@?import\\s*\\(?|;base64|base64,)|(?:\\w\\s*\\([\\w\\s]+,[\\w\\s]+,[\\w\\s]+,[\\w\\s]+,[\\w\\s]+,[\\w\\s]+\\))`,
				},
			},
		},
		{
			Name:      "Detects JavaScript DOM/miscellaneous properties and methods",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `([^*:\\s\\w,.\\/?+-]\\s*)?(?<![a-z]\\s)(?<![a-z\\/_@\\-\\|])(\\s*return\\s*)?(?:create(?:element|attribute|textnode)|[a-z]+events?|setattribute|getelement\\w+|appendchild|createrange|createcontextualfragment|removenode|parentnode|decodeuricomponent|\\wettimeout|(?:ms)?setimmediate|option|useragent)(?(1)[^\\w%\"]|(?:\\s*[^@\\s\\w%\",.+\\-]))`,
				},
			},
		},
		{
			Name:      "Detects possible includes and typical script methods",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `([^*\\s\\w,.\\/?+-]\\s*)?(?<![a-mo-z]\\s)(?<![a-z\\/_@])(\\s*return\\s*)?(?:alert|inputbox|showmod(?:al|eless)dialog|showhelp|infinity|isnan|isnull|iterator|msgbox|executeglobal|expression|prompt|write(?:ln)?|confirm|dialog|urn|(?:un)?eval|exec|execscript|tostring|status|execute|window|unescape|navigate|jquery|getscript|extend|prototype)(?(1)[^\\w%\"]|(?:\\s*[^@\\s\\w%\",.:\\/+\\-]))`,
				},
			},
		},
		{
			Name:      "Detects JavaScript object properties and methods",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `([^*:\\s\\w,.\\/?+-]\\s*)?(?<![a-z]\\s)(?<![a-z\\/_@])(\\s*return\\s*)?(?:hash|name|href|navigateandfind|source|pathname|close|constructor|port|protocol|assign|replace|back|forward|document|ownerdocument|window|top|this|self|parent|frames|_?content|date|cookie|innerhtml|innertext|csstext+?|outerhtml|print|moveby|resizeto|createstylesheet|stylesheets)(?(1)[^\\w%\"]|(?:\\s*[^@\\/\\s\\w%.+\\-]))`,
				},
			},
		},
		{
			Name:      "Detects JavaScript array properties and methods",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `([^*:\\s\\w,.\\/?+-]\\s*)?(?<![a-z]\\s)(?<![a-z\\/_@\\-\\|])(\\s*return\\s*)?(?:join|pop|push|reverse|reduce|concat|map|shift|sp?lice|sort|unshift)(?(1)[^\\w%\"]|(?:\\s*[^@\\s\\w%,.+\\-]))`,
				},
			},
		},
		{
			Name:      "Detects JavaScript string properties and methods",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `([^*:\\s\\w,.\\/?+-]\\s*)?(?<![a-z]\\s)(?<![a-z\\/_@\\-\\|])(\\s*return\\s*)?(?:set|atob|btoa|charat|charcodeat|charset|concat|crypto|frames|fromcharcode|indexof|lastindexof|match|navigator|toolbar|menubar|replace|regexp|slice|split|substr|substring|escape|\\w+codeuri\\w*)(?(1)[^\\w%\"]|(?:\\s*[^@\\s\\w%,.+\\-]))`,
				},
			},
		},
		{
			Name:      "Detects JavaScript language constructs",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\\)\\s*\\[)|([^*\":\\s\\w,.\\/?+-]\\s*)?(?<![a-z]\\s)(?<![a-z_@\\|])(\\s*return\\s*)?(?:globalstorage|sessionstorage|postmessage|callee|constructor|content|domain|prototype|try|catch|top|call|apply|url|function|object|array|string|math|if|for\\s*(?:each)?|elseif|case|switch|regex|boolean|location|(?:ms)?setimmediate|settimeout|setinterval|void|setexpression|namespace|while)(?(1)[^\\w%\"]|(?:\\s*[^@\\s\\w%\".+\\-\\/]))`,
				},
			},
		},
		{
			Name:      "Detects very basic XSS probings",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:,\\s*(?:alert|showmodaldialog|eval)\\s*,)|(?::\\s*eval\\s*[^\\s])|([^:\\s\\w,.\\/?+-]\\s*)?(?<![a-z\\/_@])(\\s*return\\s*)?(?:(?:document\\s*\\.)?(?:.+\\/)?(?:alert|eval|msgbox|showmod(?:al|eless)dialog|showhelp|prompt|write(?:ln)?|confirm|dialog|open))\\s*(?:[^.a-z\\s\\-]|(?:\\s*[^\\s\\w,.@\\/+-]))|(?:java[\\s\\/]*\\.[\\s\\/]*lang)|(?:\\w\\s*=\\s*new\\s+\\w+)|(?:&\\s*\\w+\\s*\\)[^,])|(?:\\+[\\W\\d]*new\\s+\\w+[\\W\\d]*\\+)|(?:document\\.\\w)`,
				},
			},
		},
		{
			Name:      "Detects advanced XSS probings via Script(), RexExp, constructors and XML namespaces",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:=\\s*(?:top|this|window|content|self|frames|_content))|(?:\\/\\s*[gimx]*\\s*[)}])|(?:[^\\s]\\s*=\\s*script)|(?:\\.\\s*constructor)|(?:default\\s+xml\\s+namespace\\s*=)|(?:\\/\\s*\\+[^+]+\\s*\\+\\s*\\/)`,
				},
			},
		},
		{
			Name:      "Detects JavaScript location/document property access and window access obfuscation",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\\.\\s*\\w+\\W*=)|(?:\\W\\s*(?:location|document)\\s*\\W[^({[;]+[({[;])|(?:\\(\\w+\\?[:\\w]+\\))|(?:\\w{2,}\\s*=\\s*\\d+[^&\\w]\\w+)|(?:\\]\\s*\\(\\s*\\w+)`,
				},
			},
		},
		{
			Name:      "Detects basic obfuscated JavaScript script injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:[\".]script\\s*\\()|(?:\\$\\$?\\s*\\(\\s*[\\w\"])|(?:\\/[\\w\\s]+\\/\\.)|(?:=\\s*\\/\\w+\\/\\s*\\.)|(?:(?:this|window|top|parent|frames|self|content)\\[\\s*[(,\"]*\\s*[\\w\\$])|(?:,\\s*new\\s+\\w+\\s*[,;)])`,
				},
			},
		},
		{
			Name:      "Detects obfuscated JavaScript script injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:=\\s*[$\\w]\\s*[\\(\\[])|(?:\\(\\s*(?:this|top|window|self|parent|_?content)\\s*\\))|(?:src\\s*=s*(?:\\w+:|\\/\\/))|(?:\\w+\\[(\"\\w+\"|\\w+\\|\\|))|(?:[\\d\\W]\\|\\|[\\d\\W]|\\W=\\w+,)|(?:\\/\\s*\\+\\s*[a-z\"])|(?:=\\s*\\$[^([]*\\()|(?:=\\s*\\(\\s*\")`,
				},
			},
		},
		{
			Name:      "Detects JavaScript cookie stealing and redirection attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:[^:\\s\\w]+\\s*[^\\w\\/](href|protocol|host|hostname|pathname|hash|port|cookie)[^\\w])`,
				},
			},
		},
		{
			Name:      "Detects data: URL injections, VBS injections and common URI schemes",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:(?:vbs|vbscript|data):.*[,+])|(?:\\w+\\s*=\\W*(?!https?)\\w+:)|(jar:\\w+:)|(=\\s*\"?\\s*vbs(?:ript)?:)|(language\\s*=\\s?\"?\\s*vbs(?:ript)?)|on\\w+\\s*=\\*\\w+\\-\"?`,
				},
			},
		},
		{
			Name:      "Detects IE firefoxurl injections, cache poisoning attempts and local file inclusion/execution",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:firefoxurl:\\w+\\|)|(?:(?:file|res|telnet|nntp|news|mailto|chrome)\\s*:\\s*[%&#xu\\/]+)|(wyciwyg|firefoxurl\\s*:\\s*\\/\\s*\\/)`,
				},
			},
		},
		{
			Name:      "Detects bindings and behavior injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:binding\\s?=|moz-binding|behavior\\s?=)|(?:[\\s\\/]style\\s*=\\s*[-\\\\])`,
				},
			},
		},
		{
			Name:      "Detects bindings and behavior injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:binding\\s?=|moz-binding|behavior\\s?=)|(?:[\\s\\/]style\\s*=\\s*[-\\\\])`,
				},
			},
		},
		{
			Name:      "Detects common XSS concatenation patterns 1/2",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:=\\s*\\w+\\s*\\+\\s*\")|(?:\\+=\\s*\\(\\s\")|(?:!+\\s*[\\d.,]+\\w?\\d*\\s*\\?)|(?:=\\s*\\[s*\\])|(?:\"\\s*\\+\\s*\")|(?:[^\\s]\\[\\s*\\d+\\s*\\]\\s*[;+])|(?:\"\\s*[&|]+\\s*\")|(?:\\/\\s*\\?\\s*\")|(?:\\/\\s*\\)\\s*\\[)|(?:\\d\\?.+:\\d)|(?:]\\s*\\[\\W*\\w)|(?:[^\\s]\\s*=\\s*\\/)`,
				},
			},
		},
		{
			Name:      "Detects common XSS concatenation patterns 2/2",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:=\\s*\\d*\\.\\d*\\?\\d*\\.\\d*)|(?:[|&]{2,}\\s*\")|(?:!\\d+\\.\\d*\\?\")|(?:\\/:[\\w.]+,)|(?:=[\\d\\W\\s]*\\[[^]]+\\])|(?:\\?\\w+:\\w+)`,
				},
			},
		},
		{
			Name:      "Detects possible event handlers",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:[^\\w\\s=]on(?!g\\&gt;)\\w+[^=_+-]*=[^$]+(?:\\W|\\&gt;)?)`,
				},
			},
		},
		{
			Name:      "Detects obfuscated script tags and XML wrapped HTML",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\\<\\w*:?\\s(?:[^\\>]*)t(?!rong))|(?:\\<scri)|(<\\w+:\\w+)|`,
				},
			},
		},
		{
			Name:      "Detects attributes in closing tags and conditional compilation tokens",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\\<\\/\\w+\\s\\w+)|(?:@(?:cc_on|set)[\\s@,\"=])`,
				},
			},
		},
		{
			Name:      "Detects common comment types",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:--[^\\n]*$)|(?:\\<!-|-->)|(?:[^*]\\/\\*|\\*\\/[^*])|(?:(?:[\\W\\d]#|--|{)$)|(?:\\/{3,}.*$)|(?:<!\\[\\W)|(?:\\]!>)`,
				},
			},
		},
		{
			Name:      "Detects base href injections and XML entity injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\\<base\\s+)|(?:<!(?:element|entity|\\[CDATA))`,
				},
			},
		},
		{
			Name:      "Detects possibly malicious html elements including some attributes",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\\<[\\/]?(?:[i]?frame|applet|isindex|marquee|keygen|script|audio|video|input|button|textarea|style|base|body|meta|link|object|embed|param|plaintext|xm\\w+|image|im(?:g|port)))`,
				},
			},
		},
		{
			Name:      "Detects nullbytes and other dangerous characters",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\\\\x[01fe][\\db-ce-f])|(?:%[01fe][\\db-ce-f])|(?:&#[01fe][\\db-ce-f])|(?:\\\\[01fe][\\db-ce-f])|(?:&#x[01fe][\\db-ce-f])`,
				},
			},
		},*/
		{
			Name:      "Detects MySQL comments, conditions and ch(a)r injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\)\s*when\s*\d+\s*then)|(?:\"\s*(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?or|not)\s+|\|\||\&\&)\s*\w+\()`,
				},
			},
		},
		{
			Name:      "Detects conditional SQL injection attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~])`,
				},
			},
		},
		/*{
			Name:      "Detects classic SQL injection probings 1/2",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\"\s*or\s*\"?\d)|(?:\x(?:23|27|3d))|(?:^.?\"$)|(?:(?:^[\"]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)|(?:\Winformation_schema|table_name\W)`,
				},
			},
		},
		{
			Name:      "Detects classic SQL injection probings 2/2",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\"\s*\*.+(?:or|id)\W*\"\d)|(?:\^\")|(?:^[\w\s\"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:\"[\s\d]*[^\w\s]+\W*\d\W*.*[\"\d])|(?:\"\s*[^\w\s?]+\s*[^\w\s]+\s*\")|(?:\"\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:\".*\*\s*\d)|(?:\"\s*or\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+\"[^,])`,
				},
			},
		},*/
		/*{
			Name:      "Detects basic SQL authentication bypass attempts 1/3",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: `(?:\d\"\s+\"\s+\d)|(?:^admin\s*\"|(\/\*)+\"+\s?(?:--|#|\/\*|{)?)|(?:\"\s*or\s*\"?\d)|(?:\x(?:23|27|3d))|(?:^.?\"$)|(?:(?:^[\"]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)|(?:\Winformation_schema|table_name\W)`,
				},
			},
		},*/
		/*{
			Name:      "Detects basic SQL authentication bypass attempts 2/3",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:union\\s*\\(+\\s*select)|(?:(?:n?and|x?or|not\\s|\\|\\||\\&\\&)\\s+[\\s\\w+]+(?:regexp\\s*\\(|sounds\\s+like\\s*\"|[=\\d]+x))|(\"\\s*\\d\\s*(?:--|#))|(?:\"[%&<>^=]+\\d\\s*(=|or))|(?:\"\\W*[+=]+\\W*\")|(?:\"\\s*[!=|][\\d\\s!=+-]+.*[\"(].*$)|(?:\"\\s*[!=|][\\d\\s!=]+.*\\d+$)|(?:\"\\s*like\\W+[\\w\"(])|(?:\\sis\\s*0\\W)|(?:where\\s[\\s\\w\\.,-]+\\s=)|(?:\"[<>~]+\")",
				},
			},
		},
		{
			Name:      "Detects basic SQL authentication bypass attempts 3/3",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:[\\d\\W]\\s+as\\s*[\"\\w]+\\s*from)|(?:^[\\W\\d]+\\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\\s+(?:(?:group_)concat|char|load_file)\\s?\\(?)|(?:end\\s*\\);)|(\"\\s+regexp\\W)|(?:[\\s(]load_file\\s*\\()",
				},
			},
		},
		{
			Name:      "Detects chained SQL injection attempts 1/2",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:@[\\w-]+\\s*\\()|(?:]\\s*\\(\\s*[\"!]\\s*\\w)|(?:<[?%](?:php)?.*(?:[?%]>)?)|(?:;[\\s\\w|]*\\$\\w+\\s*=)|(?:\\$\\w+\\s*=(?:(?:\\s*\\$?\\w+\\s*[(;])|\\s*\".*\"))|(?:;\\s*\\{\\W*\\w+\\s*\\()",
				},
			},
		},
		{
			Name:      "Detects chained SQL injection attempts 2/2",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:\\]@[^\\w\\s]+\\s*\\()|(?:;\\s*\\)\\s*when\\s*\\d+\\s*then)|(?:;\\s*or\\s*\\w+\\s+[^\\d\\w\\s](?:=|>|<)\\s*[^\\d\\w\\s])|(?:;\\s*\\w+\\s+[^\\d\\w\\s]+\\s*\\w+\\s*(?:=|>|<)\\s*[^\\d\\w\\s])",
				},
			},
		},
		{
			Name:      "Detects SQL benchmark and sleep injection attempts including conditional queries",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(select|;)\\s+(?:benchmark|if|sleep)\\s*?\\(\\s*\\(?\\s*\\w+)",
				},
			},
		},
		{
			Name:      "Detects MySQL UDF injection and other data/structure manipulation attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:create\\s+function\\s+\\w+\\s+returns)|(?:;\\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\\s*[\\[(]?\\w{2,})",
				},
			},
		},
		{
			Name:      "Detects MySQL charset switch and MSSQL DoS attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:alter\\s*\\w+.*character\\s+set\\s+\\w+)|(\";\\s*waitfor\\s+time\\s+\")|(?:\";.*:\\s*goto)",
				},
			},
		},
		{
			Name:      "Detects MySQL and PostgreSQL stored procedure/function injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:procedure\\s+analyse\\s*\\()|(?:;\\s*(declare|open)\\s+[\\w-]+)|(?:create\\s+(procedure|function)\\s*\\w+\\s*\\(\\s*\\)\\s*-)|(?:declare[^\\w]+[@#]\\s*\\w+)|(exec\\s*\\(\\s*@)",
				},
			},
		},
		{
			Name:      "Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:select\\s*pg_sleep)|(?:waitfor\\s*delay\\s?\"+\\s?\\d)|(?:;\\s*shutdown\\s*(?:;|--|#|\\/\\*|{))",
				},
			},
		},

		{
			Name:      "Detects MSSQL code execution and information gathering attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:\\sexec\\s+xp_cmdshell)|(?:\"\\s*!\\s*[\"\\w])|(?:from\\W+information_schema\\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\\s*\\([^\\)]*)|(?:\";?\\s*(?:select|union|having)\\s*[^\\s])|(?:\\wiif\\s*\\()|(?:exec\\s+master\\.)|(?:union\\sselect\\s@)|(?:union[\\w(\\s]*select)|(?:select.*\\w?user\\()|(?:into[\\s+]+(?:dump|out)file\\s*\")",
				},
			},
		},
		{
			Name:      "Detects MATCH AGAINST, MERGE, EXECUTE IMMEDIATE and HAVING injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:merge.*using\\s*\\()|(execute\\s*immediate\\s*\")|(?:\\W+\\d*\\s*having\\s*[^\\s\\-])|(?:match\\s*[\\w(),+-]+\\s*against\\s*\\()",
				},
			},
		},
		{
			Name:      "Detects MySQL comment-/space-obfuscated injections and backtick termination",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:,.*[)\\da-f\"]\"(?:\".*\"|\\Z|[^\"]+))|(?:\\Wselect.+\\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\\s*\\(\\s*space\\s*\\()",
				},
			},
		},
		{
			Name:      "Detects code injection attempts 1/3",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:@[\\w-]+\\s*\\()|(?:]\\s*\\(\\s*[\"!]\\s*\\w)|(?:<[?%](?:php)?.*(?:[?%]>)?)|(?:;[\\s\\w|]*\\$\\w+\\s*=)|(?:\\$\\w+\\s*=(?:(?:\\s*\\$?\\w+\\s*[(;])|\\s*\".*\"))|(?:;\\s*\\{\\W*\\w+\\s*\\()",
				},
			},
		},
		{
			Name:      "Detects code injection attempts 2/3",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(?:[;]+|(<[?%](?:php)?)).*(?:define|eval|file_get_contents|include|require|require_once|set|shell_exec|phpinfo|system|passthru|preg_\\w+|execute)\\s*[\"(@])",
				},
			},
		},
		{
			Name:      "Detects code injection attempts 3/3",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(?:[;]+|(<[?%](?:php)?)).*[^\\w](?:echo|print|print_r|var_dump|[fp]open))|(?:;\\s*rm\\s+-\\w+\\s+)|(?:;.*{.*\\$\\w+\\s*=)|(?:\\$\\w+\\s*\\[\\]\\s*=\\s*)",
				},
			},
		},
		{
			Name:      "Detects common function declarations and special JS operators",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:function[^(]*\\([^)]*\\))|(?:(?:delete|void|throw|instanceof|new|typeof)[^\\w.]+\\w+\\s*[([])|([)\\]]\\s*\\.\\s*\\w+\\s*=)|(?:\\(\\s*new\\s+\\w+\\s*\\)\\.)",
				},
			},
		},
		{
			Name:      "Detects common mail header injections",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:[\\w.-]+@[\\w.-]+%(?:[01][\\db-ce-f])+\\w+:)",
				},
			},
		},
		{
			Name:      "Detects perl echo shellcode injection and LDAP vectors",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:\\.pl\\?\\w+=\\w?\\|\\w+;)|(?:\\|\\(\\w+=\\*)|(?:\\*\\s*\\)+\\s*;)",
				},
			},
		},
		{
			Name:      "Detects basic XSS DoS attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(^|\\W)const\\s+[\\w\\-]+\\s*=)|(?:(?:do|for|while)\\s*\\([^;]+;+\\))|(?:(?:^|\\W)on\\w+\\s*=[\\w\\W]*(?:on\\w+|alert|eval|print|confirm|prompt))|(?:groups=\\d+\\(\\w+\\))|(?:(.)\\1{128,})",
				},
			},
		},
		{
			Name:      "Detects unknown attack vectors based on PHPIDS Centrifuge detection",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:\\({2,}\\+{2,}:{2,})|(?:\\({2,}\\+{2,}:+)|(?:\\({3,}\\++:{2,})|(?:\\$\\[!!!\\])",
				},
			},
		},
		{
			Name:      "Finds attribute breaking injections including obfuscated attributes",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:[\\s\\/\"]+[-\\w\\/\\\\\\*]+\\s*=.+(?:\\/\\s*>))",
				},
			},
		},
		{
			Name:      "Finds basic VBScript injection attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(?:msgbox|eval)\\s*\\+|(?:language\\s*=\\*vbscript))",
				},
			},
		},
		{
			Name:      "Finds basic MongoDB SQL injection attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:\\[\\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\\])",
				},
			},
		},
		{
			Name:      "finds malicious attribute injection attempts and MHTML attacks",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:[\\s\\d\\/\"]+(?:on\\w+|style|poster|background)=[$\"\\w])|(?:-type\\s*:\\s*multipart)",
				},
			},
		},
		{
			Name:      "Detects blind sqli tests using sleep() or benchmark().",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(sleep\\((\\s*)(\\d*)(\\s*)\\)|benchmark\\((.*)\\,(.*)\\)))",
				},
			},
		},
		{
			Name:      "An attacker is trying to locate a file to read or write.",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(\\%SYSTEMROOT\\%))",
				},
			},
		},
		{
			Name:      "Looking for a format string attack",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(((.*)\\%[c|d|i|e|f|g|o|s|u|x|p|n]){8}))",
				},
			},
		},
		{
			Name:      "Looking for basic sql injection. Common attack string for mysql, oracle and others.",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:(union(.*)select(.*)from))",
				},
			},
		},
		{
			Name:      "Looking for integer overflow attacks, these are taken from skipfish, except 2.2250738585072007e-308 is the \"magic number\" crash",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$)",
				},
			},
		},
		{
			Name:      "Detects SQL comment filter evasion",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "(?:%23.*?%0A)",
				},
			},
		},
		{
			Name:      "Detects out-of-band (OOB) interaction or Server-Side Request Forgery (SSRF) attack attempts",
			Condition: "or",
			Rules: []teler.Condition{
				{
					Method:  request.ALL,
					Element: request.Any,
					Pattern: "((burpcollaborator|pipedream)\\.net|canarytokens\\.com|oast\\.(online|(liv|sit|m)e|fun|pro))",
				},
			},
		},*/
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
