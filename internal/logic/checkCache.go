package logic

import (
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

type CacheChecker struct{}

var Checker *CacheChecker

func init() {
	Checker = NewCacheChecker()
}
func NewCacheChecker() *CacheChecker {
	return &CacheChecker{}
}

// Check 执行检查缓存的逻辑（增强版：自适应等待时间）
func (c *CacheChecker) Check(target *models.TargetStruct) error {
	isCache, orderCustomHeaders := c.IsCacheAvailable(target)
	if !isCache {
		target.Cache.NoCache = true
		return nil
	}
	target.Cache.OrderCustomHeaders = orderCustomHeaders
	initialResp := target.Response

	// 判断是否always miss
	if utils.IsCacheMiss(target, &initialResp.Header) {
		// 自适应等待时间
		waitTime := c.calculateWaitTime(target)
		gologger.Debug().Msgf("Waiting %v for cache to populate", waitTime)
		time.Sleep(waitTime)

		for i := 0; i < 3; i++ {
			tmpReq, err := utils.CloneRequest(initialResp.Request)
			if err != nil {
				gologger.Error().Msgf("Failed to clone request: %v", err)
				continue
			}

			retryResp, err := utils.CommonClient.Do(tmpReq)
			if err != nil {
				gologger.Error().Msgf("Request failed on retry %d: %v", i+1, err)
				time.Sleep(c.calculateRetryInterval(i))
				continue
			}
			if retryResp == nil {
				gologger.Warning().Msg("Received nil response")
				continue
			}

			// 立即关闭Body，不要用defer（defer在函数返回时才执行）
			isHit := utils.IsCacheHit(target, &retryResp.Header)
			utils.CloseReader(retryResp.Body)

			if isHit {
				target.Cache.NoCache = false
				gologger.Debug().Msgf("Cache hit confirmed on retry %d", i+1)
				return nil
			}

			time.Sleep(c.calculateRetryInterval(i))
		}
		gologger.Info().Msgf("The target %s has a caching mechanism but consistently results in cache misses.", target.Request.URL)
		target.Cache.NoCache = true
		return nil
	}
	target.Cache.NoCache = false
	return nil
}

// calculateWaitTime 根据CDN类型和响应特征计算合适的等待时间
func (c *CacheChecker) calculateWaitTime(target *models.TargetStruct) time.Duration {
	// 检测CDN类型
	cdnType := c.detectCDNType(target)

	switch cdnType {
	case "cloudflare", "fastly", "cloudfront":
		// 快速CDN：100-300ms
		return 200 * time.Millisecond
	case "akamai", "cdn77":
		// 中速CDN：500ms-1s
		return 800 * time.Millisecond
	case "custom", "origin":
		// 自建缓存或源站缓存：1-2s
		return 1500 * time.Millisecond
	default:
		// 未知类型：使用默认1s
		return 1 * time.Second
	}
}

// calculateRetryInterval 计算重试间隔（指数退避）
func (c *CacheChecker) calculateRetryInterval(attempt int) time.Duration {
	baseInterval := 300 * time.Millisecond
	return time.Duration(baseInterval.Milliseconds()*(1<<uint(attempt))) * time.Millisecond
}

// detectCDNType 检测CDN类型
func (c *CacheChecker) detectCDNType(target *models.TargetStruct) string {
	headers := target.Response.Header

	// Cloudflare
	if headers.Get("CF-Cache-Status") != "" || headers.Get("CF-Ray") != "" {
		return "cloudflare"
	}

	// Fastly
	if headers.Get("X-Fastly-Request-ID") != "" || headers.Get("Fastly-Debug-Digest") != "" {
		return "fastly"
	}

	// Akamai
	if headers.Get("X-Akamai-Transformed") != "" || headers.Get("Akamai-Cache-Status") != "" {
		return "akamai"
	}

	// CloudFront (AWS)
	if headers.Get("X-Amz-Cf-Id") != "" || headers.Get("X-Amz-Cf-Pop") != "" {
		return "cloudfront"
	}

	// 阿里云CDN
	if headers.Get("X-Iinfo") != "" || headers.Get("Ali-Swift-Global-Savetime") != "" {
		return "alicdn"
	}

	// CDN77
	if headers.Get("X-CDN") == "CDN77" {
		return "cdn77"
	}

	// Varnish
	if headers.Get("Via") != "" && strings.Contains(strings.ToLower(headers.Get("Via")), "varnish") {
		return "varnish"
	}

	// Nginx缓存
	if headers.Get("X-Proxy-Cache") != "" || headers.Get("X-Cache-Status") != "" {
		return "nginx"
	}

	// 检查Server头
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "cloudflare") {
		return "cloudflare"
	}
	if strings.Contains(server, "akamaighost") {
		return "akamai"
	}

	// 如果有Age头，可能是origin缓存
	if headers.Get("Age") != "" {
		return "origin"
	}

	return "unknown"
}

// IsCacheAvailable 检查目标是否存在缓存机制
// 仅仅是判断是否存在缓存机制，并不能判断是否命中缓存
func (c *CacheChecker) IsCacheAvailable(target *models.TargetStruct) (bool, map[int]string) {
	hasCustomHeaders, headers := utils.HasCustomHeaders(target.Response)
	if !hasCustomHeaders {
		return false, nil
	}

	target.Cache.Indicators = headers
	orderCustomHeaders := make(map[int]string)
	order := 0
	addHeader := func(headerName string) {
		order++
		orderCustomHeaders[order] = headerName
	}

	if utils.IsCacheValidByAge(headers) {
		addHeader("Age")
	}
	if utils.IsCacheValidByXInfo(headers) {
		addHeader("X-Iinfo")
	}
	if utils.IsCacheValidByXCacheHits(headers) {
		addHeader("X-Cache-Hits")
	}
	if utils.IsCacheValidByOtherCustomHeaders(headers) {
		addHeader("Others")
	}
	if len(orderCustomHeaders) != 0 {
		return true, orderCustomHeaders
	}
	return false, nil
}
