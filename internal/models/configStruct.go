package internal

import "github.com/wealeson1/wcpvs/pkg/utils"

var Config ConfigStruct

type ConfigStruct struct {
	HeaderWordlist    string
	QueryWordlist     string
	Threads           int
	ReqRate           float64
	Verbosity         int
	DoPost            bool
	ContentType       string
	QuerySeparator    string
	CacheBuster       string
	TimeOut           int
	DeclineCookies    bool
	Force             bool
	UseHTTP           bool
	CLDiff            int
	HMDiff            int
	CacheHeader       string
	DisableColor      bool
	IgnoreStatus      []int
	RecInclude        string
	RecExclude        []string
	RecDomains        []string
	RecLimit          int
	Urls              []string
	Cookies           []string
	Headers           []string
	Parameters        []string
	Body              string
	OnlyTest          string
	SkipTest          string
	GeneratePath      string
	GenerateReport    bool
	EscapeJSON        bool
	GenerateCompleted bool
	ProxyCertPath     string
	ProxyURL          string
	Crawler           bool
	TargetStruct      TargetStruct
}

func init() {
	headers, err := utils.ReadFileToSlice("/Users/will/Desktop/ToolDevelopment/wcpvs/static/headers")
	if err != nil || headers == nil {
		panic(err)
	}
	Config = ConfigStruct{
		Headers: headers,
	}
}
