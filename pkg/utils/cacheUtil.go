package utils

import (
	"github.com/wealeson1/wcpvs/internal/models"
	"net/http"
	"strconv"
	"strings"
)

// IsCacheMiss 根据响应的 Header 判断是否命中缓存，未命中返回true，命中返回false
func IsCacheMiss(target *models.TargetStruct, headers *http.Header) bool {
	if len(target.Cache.Indicators) == 0 {
		return false
	}
	if CacheMissByAge(headers) || CacheMissByXCH(headers) || CacheMissByXI(headers) || CacheMissByOthers(target, headers) {
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
	isCacheValid := (ageValue == 1) || (ageValue == 0)
	return isCacheValid
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
	if xInfo == "" {
		return false
	}
	isCacheValid := strings.Contains(xInfo[22:23], "C") || strings.Contains(xInfo[22:23], "V")
	return isCacheValid
}

// CacheMissByOthers 判断缓存是否命中，根据响应中的其他可疑头
func CacheMissByOthers(target *models.TargetStruct, headers *http.Header) bool {
	customHeaderOfTarget := target.Cache.Indicators
	for header, _ := range customHeaderOfTarget {
		headerValues := strings.ToLower(headers.Get(header))
		if headerValues == "" || strings.Contains(headerValues, "miss") {
			return true
		}
	}
	return false
}

// CacheMissByExpires 判断缓存是否命中，根据响应中的 Expires 头
func CacheMissByExpires(target *models.TargetStruct, headers *http.Header) bool {
	//todo
	return false
}
