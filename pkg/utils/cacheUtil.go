package utils

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/wealeson1/wcpvs/internal/models"
)

// IsCacheMiss 根据响应的 Header 判断是否命中缓存，未命中返回true，命中返回false
func IsCacheMiss(target *models.TargetStruct, headers *http.Header) bool {
	if len(target.Cache.Indicators) == 0 {
		return false
	}
	if CacheMissByAge(headers) {
		return true
	}
	if CacheMissByXCH(headers) || CacheMissByXI(headers) || CacheMissByOthers(target, headers) {
		return true
	}
	return false
}

func IsCacheHit(target *models.TargetStruct, headers *http.Header) bool {
	if len(target.Cache.Indicators) == 0 {
		return false
	}
	// 根据Age头判断：Age=0是Miss，Age>=1是Hit
	if headers.Get("age") != "" {
		ageValue, err := strconv.Atoi(headers.Get("age"))
		if err != nil {
			return false
		}
		if ageValue == 0 {
			return false // Miss: 刚从源站获取
		}
		if ageValue >= 1 {
			return true // Hit: 从缓存获取（已存在>=1秒）
		}
	}

	if IsCacheValidByXCacheHits(*headers) || IsCacheValidByXInfo(*headers) || IsCacheValidByOtherCustomHeaders(*headers) {
		return true
	}
	return false
}

// CacheMissByAge 判断缓存是否命中，根据响应中的Age
func CacheMissByAge(headers *http.Header) bool {
	age := headers.Get("Age")
	if age == "" {
		return false
	}
	ageValue, err := strconv.Atoi(age)
	if err != nil {
		return false
	}
	// Age=0表示刚从源站获取（Miss）
	// Age>=1表示从缓存获取（Hit）
	return ageValue == 0
}

// CacheMissByXCH 判断缓存是否命中，根据响应中的X-Cache-Hits
func CacheMissByXCH(headers *http.Header) bool {
	xCacheHits := headers.Get("X-Cache-Hits")
	if xCacheHits == "" {
		return false
	}
	// 根据 x-cache-hits 的值来确定缓存是否有效
	splitValues := strings.Split(xCacheHits, ",")
	for _, x := range splitValues {
		x = strings.TrimSpace(x)
		if x == "0" {
			return true
		}
	}
	return false
}

// CacheMissByXI 判断缓存是否命中，根据响应中的X-Iinfo
func CacheMissByXI(headers *http.Header) bool {
	xInfo := headers.Get("X-Iinfo")
	if xInfo == "" || len(xInfo) < 23 {
		return false
	}
	// 阿里云CDN：第23位字符表示缓存状态
	// C = Hit from Cache, V = Hit from Cache(Valid)
	// M = Miss (from origin), N = Not cacheable
	char := xInfo[22:23]
	// Miss的标识：不是C也不是V
	return char != "C" && char != "V"
}

// CacheMissByOthers 判断缓存是否命中，根据响应中的其他可疑头（使用投票机制）
func CacheMissByOthers(target *models.TargetStruct, headers *http.Header) bool {
	if len(target.Cache.Indicators) == 0 {
		return false
	}

	customHeaderOfTarget := target.Cache.Indicators
	hitCount := 0
	missCount := 0

	// 收集所有header的投票
	for header := range customHeaderOfTarget {
		headerValue := headers.Get(header)
		if headerValue == "" {
			continue
		}
		headerValues := strings.ToLower(headerValue)

		// Hit的标识
		if strings.Contains(headerValues, "hit") || strings.Contains(headerValues, "cached") || strings.Contains(headerValues, "from cache") {
			hitCount++
		}
		// Miss的标识
		if strings.Contains(headerValues, "miss") || strings.Contains(headerValues, "bypass") || strings.Contains(headerValues, "uncached") || strings.Contains(headerValues, "not cached") {
			missCount++
		}
	}

	// 优先级：如果有明确的Hit，优先信任Hit
	if hitCount > 0 {
		return false
	}

	// 如果有Miss标识，返回true
	if missCount > 0 {
		return true
	}

	return false
}

// CacheMissByExpires 判断缓存是否命中，根据响应中的 Expires 头
func CacheMissByExpires(target *models.TargetStruct, headers *http.Header) bool {
	//todo
	return false
}

var CustomHeaders = []string{
	"cache-control",
	"pragma",
	"x-cache-lookup",
	"x-cache",
	"cf-cache-status",
	"x-drupal-cache",
	"x-varnish-cache",
	"akamai-cache-status",
	"server-timing",
	"x-iinfo",
	"x-nc",
	"x-hs-cf-cache-status",
	"x-proxy-cache",
	"x-cache-hits",
	"x-cache-status",
	"x-cache-info",
	"x-rack-cache",
	"cdn_cache_status",
	"x-akamai-cache",
	"x-akamai-cache-remote",
	"x-cache-remote",
	"X-Response-Cache",
	"age",
	"x-cache-webcdn",
	"expires",
	"date",
	"eo-cache-status",
	"cache-status",
	"ec-cdn-status",
	"x-vercel-cache", // Vercel
	"cdn-cache",      // Bunny CDN
}

// HasCustomHeaders 检查响应中是否存在 customHeaders 中的响应头
// respHeaders 必须是两个请求的后一个响应的响应头
func HasCustomHeaders(resp *http.Response) (bool, map[string][]string) {
	hasCustomHeaders := make(map[string][]string)
	// for header, values := range resp.Header {
	// 	if slices.Contains(CustomHeaders, strings.ToLower(header)) {
	// 		hasCustomHeaders[header] = values
	// 	}
	// }
	for header, values := range resp.Header {
		lowerCaseHeader := strings.ToLower(header)
		for _, customHeader := range CustomHeaders {
			if lowerCaseHeader == strings.ToLower(customHeader) {
				hasCustomHeaders[header] = values
				break
			}
		}
	}
	if len(hasCustomHeaders) == 0 {
		return false, nil
	}
	return true, hasCustomHeaders
}

// IsCacheValidByExpires 根据 Expire 和 Date 判断是否存在缓存机制
func IsCacheValidByExpires(headers http.Header) bool {
	expires := headers.Get("Expires")
	date := headers.Get("Date")

	if expires == "" || date == "" {
		return false
	}

	expiresTime, err := http.ParseTime(expires)
	if err != nil {
		return false
	}

	dateTime, err := http.ParseTime(date)
	if err != nil {
		return false
	}

	isCacheValid := dateTime.Before(expiresTime)
	if isCacheValid {
		//gologger.Info().Msgf("Cache mechanism exists, judgment basis Expires:%s date:%s.", expires, date)
	}
	return isCacheValid
}

// IsCacheValidByXInfo 根据响应头中的 x-iinfo 判断缓存是否有效
func IsCacheValidByXInfo(headers http.Header) bool {
	xInfo := headers.Get("X-Iinfo")
	if xInfo == "" || len(xInfo) < 23 {
		return false
	}
	// 阿里云CDN：第23位字符表示缓存状态
	char := xInfo[22:23]
	isCacheValid := char == "C" || char == "V"
	// 根据 x-iinfo 的值来确定缓存是否有效
	if isCacheValid {
		//gologger.Info().Msgf("Cache mechanism exists, judgment basis xInfo:%s.", xInfo)
	}
	return isCacheValid
}

// IsCacheValidByXCacheHits 根据响应头中的 x-cache-hits 判断缓存是否有效
func IsCacheValidByXCacheHits(headers http.Header) bool {
	xCacheHits := headers.Get("X-Cache-Hits")
	if xCacheHits == "" {
		return false
	}
	// 根据 x-cache-hits 的值来确定缓存是否有效
	splitValues := strings.Split(xCacheHits, ",")
	for _, x := range splitValues {
		x = strings.TrimSpace(x)
		if x != "0" {
			//gologger.Info().Msgf("Cache mechanism exists, judgment basis X-Cache-Hits:%s.", xCacheHits)
			return true
		}
	}
	return false
}

// IsCacheValidByAge 根据响应头中的 Age 判断是否命中缓存
func IsCacheValidByAge(headers http.Header) bool {
	age := headers.Get("Age")
	if age == "" {
		return false
	}
	ageValue, err := strconv.Atoi(age)
	if err != nil {
		return false
	}
	isCacheValid := ageValue > 0
	// 根据需求定义 Age 是否有效的条件
	return isCacheValid
}

// IsCacheValidByOtherCustomHeaders 根据其他的 CustomHeaders 判断是否存在缓存机制
func IsCacheValidByOtherCustomHeaders(headers http.Header) bool {
	for _, header := range CustomHeaders {
		headerValues := strings.ToLower(headers.Get(header))
		if strings.Contains(headerValues, "miss") && strings.Contains(headerValues, "hit") {
			return false
		}
		if strings.Contains(headerValues, "hit") || strings.Contains(headerValues, "cached") || strings.Contains(headerValues, "expired") {
			return true
		}
	}
	return false
}
