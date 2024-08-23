package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"sync"
)

var lock sync.Mutex

type Crawler struct {
	Katana *utils.Crawler
}

var CrawlerInstance *Crawler

func CrawlerInit() {
	CrawlerInstance = NewCrawler()
}

func NewCrawler() *Crawler {
	options := types.Options{
		MaxDepth:           ScanOptions.MaxDepth, // Maximum depth to crawl
		FieldScope:         "rdn",                // Crawling Scope Field
		BodyReadSize:       10240,                // Maximum response size to read
		Timeout:            ScanOptions.TimeOut,  // Timeout is the time to wait for request in seconds
		Concurrency:        5,                    // Concurrency is the number of concurrent crawling goroutines
		Parallelism:        10,                   // Parallelism is the number of urls processing goroutines
		Delay:              0,                    // Delay is the delay between each crawl requests in seconds
		RateLimit:          50,                   // Maximum requests to send per second
		Strategy:           "depth-first",        // Visit strategy (depth-first, breadth-first)
		Headless:           ScanOptions.Headless,
		UseInstalledChrome: ScanOptions.SystemChrome,
		Proxy:              ScanOptions.ProxyURL,
		IgnoreQueryParams:  true,
	}

	crawlerOptions, err := types.NewCrawlerOptions(&options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
		panic(err)
	}

	crawler, err := utils.NewCrawler(crawlerOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	return &Crawler{
		Katana: crawler,
	}
}

// Crawl 只能单线程
func (c *Crawler) Crawl(url string) ([]string, error) {
	lock.Lock()
	defer lock.Unlock()
	// 每次都要清空
	urls := make([]string, 0)

	c.Katana.Options.Options.OnResult = func(result output.Result) {
		if result.Response.StatusCode < 500 {
			url := result.Request.URL
			urls = append(urls, url)
		}
	}
	var input = url
	err := c.Katana.Crawl(input)
	if err != nil {
		gologger.Warning().Msgf("Could not crawl %s: %s", input, err.Error())
		return nil, nil
	}
	return urls, nil
}
