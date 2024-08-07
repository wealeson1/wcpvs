package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"math"
)

var Results []output.Result

func init() {
	Results = make([]output.Result, 0)
}

func Crawl(url string, targets chan *models.TargetStruct) {
	options := &types.Options{
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
		OnResult: func(result output.Result) { // Callback function to execute for result
			if result.HasResponse() {
				req := result.Response.Resp.Request
				target := &models.TargetStruct{
					Request:  req,
					Response: result.Response.Resp,
					Cache:    &models.CacheStruct{},
					RespBody: []byte(result.Response.Body),
				}
				targets <- target
				return
			}

			resp, err := utils.CommonClient.Get(result.Request.RequestURL())
			if err != nil {
				gologger.Error().Msgf("%s\n", err)
				return
			}
			defer resp.Body.Close()
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}

			target := &models.TargetStruct{
				Request:  resp.Request,
				Response: resp,
				Cache:    &models.CacheStruct{},
				RespBody: respBody,
			}
			targets <- target
		},
	}
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer func(crawlerOptions *types.CrawlerOptions) {
		err := crawlerOptions.Close()
		if err != nil {

		}
	}(crawlerOptions)
	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer func(crawler *standard.Crawler) {
		err := crawler.Close()
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}(crawler)
	var input = url
	err = crawler.Crawl(input)
	if err != nil {
		gologger.Warning().Msgf("Could not crawl %s: %s", input, err.Error())
	}
}
