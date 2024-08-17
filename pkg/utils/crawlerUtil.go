package utils

import (
	"bytes"
	"context"
	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/common"
	"github.com/projectdiscovery/katana/pkg/engine/parser"
	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/remeh/sizedwaitgroup"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Crawler is a standard crawler instance
type Crawler struct {
	*common.Shared
}

// NewCrawler returns a new standard crawler instance
func NewCrawler(options *types.CrawlerOptions) (*Crawler, error) {
	shared, err := common.NewShared(options)
	if err != nil {
		return nil, errorutil.NewWithErr(err).WithTag("standard")
	}
	return &Crawler{Shared: shared}, nil
}

// Close closes the crawler process
func (c *Crawler) Close() error {
	return nil
}

// Crawl crawls a URL with the specified options
func (c *Crawler) Crawl(rootURL string) error {
	crawlSession, err := c.NewCrawlSessionWithURL(rootURL)
	if err != nil {
		return errorutil.NewWithErr(err).WithTag("standard")
	}
	defer crawlSession.CancelFunc()
	gologger.Info().Msgf("Started standard crawling for => %v", rootURL)
	if err := c.Do(crawlSession, c.makeRequest); err != nil {
		return errorutil.NewWithErr(err).WithTag("standard")
	}
	return nil
}

func (c *Crawler) Output(navigationRequest *navigation.Request, navigationResponse *navigation.Response, passiveReference *navigation.PassiveReference, err error) {
	var errData string
	if err != nil {
		errData = err.Error()
	}
	// Write the found result to output
	result := &output.Result{
		Timestamp:        time.Now(),
		Request:          navigationRequest,
		Response:         navigationResponse,
		PassiveReference: passiveReference,
		Error:            errData,
	}

	//outputErr := c.Options.OutputWriter.Write(result)

	//if c.Options.Options.OnResult != nil && outputErr == nil {
	if c.Options.Options.OnResult != nil {
		c.Options.Options.OnResult(*result)
	}
}

// makeRequest makes a request to a URL returning a response interface.
func (c *Crawler) makeRequest(s *common.CrawlSession, request *navigation.Request) (*navigation.Response, error) {
	response := &navigation.Response{
		Depth:        request.Depth + 1,
		RootHostname: s.Hostname,
	}
	ctx := context.WithValue(s.Ctx, navigation.Depth{}, request.Depth)
	httpReq, err := http.NewRequestWithContext(ctx, request.Method, request.URL, nil)
	if err != nil {
		return response, err
	}
	if request.Body != "" && request.Method != "GET" {
		httpReq.Body = io.NopCloser(strings.NewReader(request.Body))
	}
	req, err := retryablehttp.FromRequest(httpReq)
	if err != nil {
		return response, err
	}
	req.Header.Set("User-Agent", utils.WebUserAgent())

	// Set the headers for the request.
	for k, v := range request.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	resp, err := s.HttpClient.Do(req)
	if resp != nil {
		defer func() {
			if resp.Body != nil && resp.StatusCode != http.StatusSwitchingProtocols {
				_, _ = io.Copy(io.Discard, resp.Body)
			}
			_ = resp.Body.Close()
		}()
	}

	rawRequestBytes, _ := req.Dump()
	request.Raw = string(rawRequestBytes)

	if err != nil {
		return response, err
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return response, nil
	}
	limitReader := io.LimitReader(resp.Body, int64(c.Options.Options.BodyReadSize))
	data, err := io.ReadAll(limitReader)
	if err != nil {
		return response, err
	}
	if !c.Options.UniqueFilter.UniqueContent(data) {
		return &navigation.Response{}, nil
	}

	technologies := c.Options.Wappalyzer.Fingerprint(resp.Header, data)
	response.Technologies = mapsutil.GetKeys(technologies)

	resp.Body = io.NopCloser(strings.NewReader(string(data)))

	response.Body = string(data)
	response.Resp = resp
	response.Reader, err = goquery.NewDocumentFromReader(bytes.NewReader(data))
	response.Reader.Url, _ = url.Parse(request.URL)
	response.StatusCode = resp.StatusCode
	response.Headers = utils.FlattenHeaders(resp.Header)
	if c.Options.Options.FormExtraction {
		response.Forms = append(response.Forms, utils.ParseFormFields(response.Reader)...)
	}

	resp.ContentLength = int64(len(data))

	rawResponseBytes, _ := httputil.DumpResponse(resp, true)
	response.Raw = string(rawResponseBytes)

	if err != nil {
		return response, errorutil.NewWithTag("standard", "could not make document from reader").Wrap(err)
	}

	return response, nil
}

func (c *Crawler) Do(crawlSession *common.CrawlSession, doRequest common.DoRequestFunc) error {
	wg := sizedwaitgroup.New(c.Options.Options.Concurrency)
	for item := range crawlSession.Queue.Pop() {
		if ctxErr := crawlSession.Ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		req, ok := item.(*navigation.Request)
		if !ok {
			continue
		}

		if !utils.IsURL(req.URL) {
			gologger.Debug().Msgf("`%v` not a url. skipping", req.URL)
			continue
		}

		if ok, err := c.Options.ValidateScope(req.URL, crawlSession.Hostname); err != nil || !ok {
			gologger.Debug().Msgf("`%v` not in scope. skipping", req.URL)
			continue
		}

		wg.Add()
		// gologger.Debug().Msgf("Visting: %v", req.URL) // not sure if this is needed
		go func() {
			defer wg.Done()

			c.Options.RateLimit.Take()

			// Delay if the user has asked for it
			if c.Options.Options.Delay > 0 {
				time.Sleep(time.Duration(c.Options.Options.Delay) * time.Second)
			}

			resp, err := doRequest(crawlSession, req)

			c.Output(req, resp, nil, err)

			if err != nil {
				gologger.Warning().Msgf("Could not request seed URL %s: %s\n", req.URL, err)
				outputError := &output.Error{
					Timestamp: time.Now(),
					Endpoint:  req.RequestURL(),
					Source:    req.Source,
					Error:     err.Error(),
				}
				_ = c.Options.OutputWriter.WriteErr(outputError)
				return
			}
			if resp.Resp == nil || resp.Reader == nil {
				return
			}
			if c.Options.Options.DisableRedirects && resp.IsRedirect() {
				return
			}

			navigationRequests := parser.ParseResponse(resp)
			c.Enqueue(crawlSession.Queue, navigationRequests...)
		}()
	}
	wg.Wait()
	return nil
}
