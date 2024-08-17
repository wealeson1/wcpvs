package runner

import "testing"

func TestCrawler_Crawl(t *testing.T) {
	urls, err := CrawlerInstance.Crawl("https://www.baidu.com")
	if err != nil {
		t.Error(err)
	}
	t.Log(urls)
}
