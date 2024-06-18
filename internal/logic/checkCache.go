package logic

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"time"
)

type CacheChecker struct{}

var Checker *CacheChecker

func init() {
	Checker = NewCacheChecker()
}
func NewCacheChecker() *CacheChecker {
	return &CacheChecker{}
}

// Check 执行检查缓存的逻辑
func (c *CacheChecker) Check(target *models.TargetStruct) error {
	isCache, orderCustomHeaders := c.IsCacheAvailable(target)
	if !isCache {
		target.Cache.NoCache = true
	}
	target.Cache.OrderCustomHeaders = orderCustomHeaders
	resp := target.Response
	// 判断是否away miss
	if utils.IsCacheMiss(target, &resp.Header) {
		for range 3 {
			tmpReq, err := utils.CloneRequest(resp.Request)
			if err != nil {
				return err
			}
			time.Sleep(500 * time.Millisecond)
			resp, err := utils.CommonClient.Do(tmpReq)
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("second response is nil")
			}
			if !utils.IsCacheMiss(target, &resp.Header) {
				target.Cache.NoCache = false
				return nil
			}
			utils.CloseReader(resp.Body)
		}
		gologger.Info().Msgf("The target %s has a caching mechanism but consistently results in cache misses.", target.Request.URL)
		target.Cache.NoCache = true
		return nil
	}
	target.Cache.NoCache = false
	return nil
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
