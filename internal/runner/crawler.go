package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"math"
	"sync"
)

var lock sync.Mutex

type Crawler struct {
	Options *types.Options
}

var CrawlerInstance *Crawler

func CrawlerInit() {
	CrawlerInstance = NewCrawler()
}

func NewCrawler() *Crawler {
	options := types.Options{
		MaxDepth:           ScanOptions.MaxDepth, // Maximum depth to crawl
		FieldScope:         "rdn",                // Crawling Scope Field
		BodyReadSize:       math.MaxInt,          // Maximum response size to read
		Timeout:            ScanOptions.TimeOut,  // Timeout is the time to wait for request in seconds
		Concurrency:        10,                   // Concurrency is the number of concurrent crawling goroutines
		Parallelism:        10,                   // Parallelism is the number of urls processing goroutines
		Delay:              0,                    // Delay is the delay between each crawl requests in seconds
		RateLimit:          150,                  // Maximum requests to send per second
		Strategy:           "depth-first",        // Visit strategy (depth-first, breadth-first)
		Headless:           ScanOptions.Headless,
		UseInstalledChrome: ScanOptions.SystemChrome,
		Proxy:              ScanOptions.ProxyURL,
		IgnoreQueryParams:  true,
	}

	return &Crawler{
		Options: &options,
	}
}

// Crawl 只能单线程
func (c *Crawler) Crawl(url string) ([]string, error) {
	lock.Lock()
	defer lock.Unlock()
	// 每次都要清空
	urls := make([]string, 0)
	crawlerOptions, err := types.NewCrawlerOptions(c.Options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
		return nil, err
	}

	crawlerOptions.Options.OnResult = func(result output.Result) {
		if result.Response.StatusCode < 500 {
			url := result.Request.URL
			urls = append(urls, url)
		}
	}

	defer func(crawlerOptions *types.CrawlerOptions) {
		err := crawlerOptions.Close()
		if err != nil {
			return
		}
	}(crawlerOptions)

	crawler, err := utils.NewCrawler(crawlerOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	defer func(crawler *utils.Crawler) {
		err := crawler.Close()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}(crawler)

	var input = url
	err = crawler.Crawl(input)
	if err != nil {
		gologger.Warning().Msgf("Could not crawl %s: %s", input, err.Error())
		return nil, nil
	}
	return urls, nil
}
