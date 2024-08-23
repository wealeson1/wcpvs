package runner

import (
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

var (
	lock            sync.Mutex
	CrawlerInstance *Crawler
	once            sync.Once
	urlsPool        = sync.Pool{
		New: func() interface{} {
			return make([]string, 0, 100)
		},
	}
)

type Crawler struct {
	Katana *utils.Crawler
}

func CrawlerInit() {
	once.Do(func() {
		CrawlerInstance = NewCrawler()
	})
}

func NewCrawler() *Crawler {
	options := types.Options{
		MaxDepth:           ScanOptions.MaxDepth,
		FieldScope:         "rdn",
		BodyReadSize:       10240,
		Timeout:            ScanOptions.TimeOut,
		Concurrency:        5,
		Parallelism:        10,
		Delay:              0,
		RateLimit:          50,
		Strategy:           "depth-first",
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

	// 从 sync.Pool 获取 urls 切片
	urls := urlsPool.Get().([]string)
	defer urlsPool.Put(urls[:0]) // 归还切片到池中，并清空内容

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
