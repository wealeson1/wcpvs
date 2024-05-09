package logic

import (
	"errors"
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal"
	"net/http"
	"slices"
	"strings"
)

var customHeaders = []string{"cache-control", "pragma", "x-cache-lookup", "x-cache", "cf-cache-status", "x-drupal-cache", "x-varnish-cache", "akamai-cache-status", "server-timing", "x-iinfo", "x-nc", "x-hs-cf-cache-status", "x-proxy-cache", "x-cache-hits", "x-cache-status", "x-cache-info", "x-rack-cache", "cdn_cache_status", "x-akamai-cache", "x-akamai-cache-remote", "x-cache-remote", "X-Response-Cache", "age"}

type CheckCache struct {
	Targets []*internal.TargetStruct
}

func NewCheckCache(targets []*internal.TargetStruct) *CheckCache {
	return &CheckCache{
		Targets: targets,
	}
}

// Run 开始检查
func (c *CheckCache) Run() (targets []*internal.TargetStruct, err error) {
	if len(c.Targets) == 0 {
		err = errors.New("no targets found")
		gologger.Error().Msg(err.Error())
		return nil, err
	}
	for _, target := range c.Targets {
		targetIsHasCache, keys := c.IsCacheAvailable(target)
		if !targetIsHasCache {
			gologger.Print().Msgf("%s 目标不存在缓存机制，或者总是miss", target.Request.URL)
		}
		target.Cache.Indicator = keys
		gologger.Print().Msgf("%s 目标存在缓存机制，标识是 %s", target.Request.URL, keys)
	}
	return targets, nil
}

// IsCacheAvailable 检查目标是否存在缓存机制
func (c *CheckCache) IsCacheAvailable(target *internal.TargetStruct) (bool, []string) {
	isHasCustomHeader, customHeaderMap := c.HasCustomHeaders(&target.Response.Header)
	if !isHasCustomHeader {
		return false, nil
	}
	isAlwaysMiss, keys := c.IsAlwaysMiss(customHeaderMap)
	if !isAlwaysMiss {
		return false, nil
	}
	return true, keys
}

// HasCustomHeaders 检查响应中是否存在 customHeaders 中的响应头
// respHeaders 必须是两个请求的后一个响应的响应头
func (c *CheckCache) HasCustomHeaders(respHeaders *http.Header) (bool, map[string][]string) {
	hasCustomHeaders := make(map[string][]string)
	for header, values := range *respHeaders {
		if slices.Contains(customHeaders, strings.ToLower(header)) {
			hasCustomHeaders[header] = values
		}
	}
	if len(hasCustomHeaders) == 0 {
		return false, nil
	}
	return true, hasCustomHeaders
}

// IsAlwaysMiss  判断缓存命中是否总是miss
func (c *CheckCache) IsAlwaysMiss(headerIndicators map[string][]string) (bool, []string) {
	headers := make([]string, 1)
	// 保险起见还是判断一下是否为空，因为不是内部函数，防止比较奇怪的bug
	if len(headerIndicators) == 0 {
		panic(errors.New("headerIndicators 为空的话，不应该走到这！"))
	}
	for key, values := range headerIndicators {
		lowerKey := strings.ToLower(key)
		value := strings.ToLower(strings.TrimSpace(values[0]))
		if c.IsCacheHit(lowerKey, value) {
			headers = append(headers, key)
		}
	}
	return true, headers
}

// IsCacheHit 根据响应头和值判断是否命中缓存
func (c *CheckCache) IsCacheHit(key, value string) bool {
	// 判断key 和 value 是否为空
	if strings.EqualFold(key, "") || strings.EqualFold(value, "") {
		return false
	}
	switch key {
	case "age":
		if !strings.EqualFold(value, "0") {
			return true
		}
	case "x-iinfo":
		if strings.EqualFold(value[22:23], "C") || strings.EqualFold(value[22:23], "V") {
			return true
		}
	case "x-cache-hits":
		splitValues := strings.Split(value, ",")
		for _, x := range splitValues {
			x = strings.TrimSpace(x)
			if x != "0" {
				return true
			}
		}
	default:
		if strings.Contains(value, "hit") || strings.Contains(value, "cached") {
			return true
		}
	}
	return false
}
