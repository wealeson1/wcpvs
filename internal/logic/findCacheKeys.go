package logic

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"net/http"
	"strings"
	"sync"
	"time"
)

type FindCacheKeys struct {
	HeaderWordList []string
}

var CacheKeysFinder *FindCacheKeys

func init() {
	CacheKeysFinder = NewFindCacheKeys()
}

// NewFindCacheKeys 构造函数
func NewFindCacheKeys() *FindCacheKeys {
	headerWordList := make([]string, 0)
	for _, h := range models.Config.Headers {
		headerWordList = append(headerWordList, h)
	}
	return &FindCacheKeys{
		HeaderWordList: headerWordList,
	}
}

func (f *FindCacheKeys) Check(target *models.TargetStruct) error {

	if target.Cache.NoCache {
		//gologger.Info().Msgf("Target %s", target.Request.URL)
		return nil
	}

	if f.FindCacheKeyByGet(target) {
		gologger.Info().Msgf("The target %s treats all GET parameters as cache keys.", target.Request.URL)
		target.Cache.CKIsAnyGet = true
	}

	if ih, headers := f.BinarySearchHeaders(target); ih && len(headers) != 0 {
		gologger.Info().Msgf("The target %s has a request header cache key(s): %v.", target.Request.URL, headers)
		target.Cache.CKIsHeader = true
		target.Cache.HeaderCacheKeys = headers
	}

	if target.Cache.CKIsAnyGet || target.Cache.CKIsHeader {
		resp, err := tecniques.GetResp(target, tecniques.COOKIE, map[string]string{utils.RandomString(5): utils.RandomString(5)})
		if err != nil {
			return err
		}
		for h, v := range resp.Header {
			if strings.EqualFold(h, "Set-Cookie") {
				for _, hv := range v {
					splitCookieName := strings.Split(hv, ";")
					if splitCookieName[0] != "" && strings.Contains(splitCookieName[0], "=") {
						cookieName := strings.Split(splitCookieName[0], "=")[0]
						cookieValue := strings.Split(splitCookieName[0], "=")[1]
						cookie := &http.Cookie{Name: cookieName, Value: cookieValue}
						target.Request.AddCookie(cookie)
					}
				}
			}
		}
	}
	if ic, cookies := f.FindCacheKeyByCookie(target); ic && len(cookies) != 0 {
		gologger.Info().Msgf("The target %s has a cookie cache key: %v.", target.Request.URL, cookies)
		target.Cache.CKisCookie = true
		target.Cache.CookieCacheKeys = cookies
	}

	if !target.Cache.CKIsAnyGet && !target.Cache.CKIsHeader && !target.Cache.CKisCookie {
		target.Cache.NoCache = true
	}

	return nil
}

// FindCacheKeyByGet 判断是缓存机制是否忽略GET
func (f *FindCacheKeys) FindCacheKeyByGet(target *models.TargetStruct) bool {
	if len(target.Cache.Indicators) == 0 || target.Cache.NoCache {
		return false
	}

	tmpRequest, err := utils.CloneRequest(target.Request)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return false
	}

	for range 3 {
		randomParamName := utils.RandomString(5)
		randomParamValue := utils.RandomString(5)
		time.Sleep(500 * time.Millisecond)
		tmpResp, err := f.GetRespByDefGetParams(tmpRequest, randomParamName, randomParamValue)
		if err != nil {
			gologger.Error().Msg("FindCacheKeyByGet:" + err.Error())
			return false
		}
		tmpRespHeaders := &tmpResp.Header
		if utils.IsCacheHit(target, tmpRespHeaders) {
			return false
		}
		return true
	}
	return false
}

func (f *FindCacheKeys) BinarySearchHeaders2(target *models.TargetStruct) (bool, []string) {
	// 使用WaitGroup来等待所有goroutines完成
	var wg sync.WaitGroup
	// 缓存键
	var headerValues sync.Map
	// 闭包函数，用于递归调用
	var search func(target *models.TargetStruct, headers []string)
	search = func(target *models.TargetStruct, headers []string) {
		// 每次递归调用结束时减少计数
		defer wg.Done()
		// 递归结束条件
		if len(headers) == 0 {
			return
		}
		mid := len(headers) / 2
		leftPart := headers[:mid]
		rightPart := headers[mid:]
		// 克隆请求和获取响应的逻辑放在递归调用之前，以避免重复
		tmpReq, _ := utils.CloneRequest(target.Request)
		hvMap := make(map[string]string, len(headers))
		for _, h := range headers {
			hvMap[h] = utils.RandomString(5)
		}
		resp, err := f.GetRespByDefHeader(tmpReq, hvMap, target.Response.StatusCode)
		// 检查响应，如果resp为nil，则直接返回，避免关闭空的Body
		if resp != nil {
			// 使用defer确保关闭
			defer utils.CloseReader(resp.Body)
			// 如果resp不为nil且hvMap的长度为1,重复判断下是否未命中缓存，防止目标站点存在极短缓存时间的状况
			if len(hvMap) == 1 {
				// 异常状态码忽略，例如If-Match等
				if resp.StatusCode != target.Response.StatusCode {
					return
				}
				// 如果命中缓存
				if utils.IsCacheMiss(target, &resp.Header) {
					// 线程安全
					for h, v := range hvMap {
						headerValues.Store(h, v)
					}
				}
				// 命中缓存或者未命中缓存，结束递归
				return
			}
		}

		// 进行递归调用
		if err != nil || (resp != nil && utils.IsCacheMiss(target, &resp.Header)) {
			wg.Add(2)                    // 增加WaitGroup的计数
			go search(target, leftPart)  // 递归搜索左半部分
			go search(target, rightPart) // 递归搜索右半部分
		}
	}
	// 初始化WaitGroup计数
	wg.Add(1)
	search(target, f.HeaderWordList)
	wg.Wait()
	cacheKeyList := make([]string, 0)
	headerValues.Range(
		func(key, value interface{}) bool {
			cacheKeyList = append(cacheKeyList, key.(string))
			return true
		})
	if len(cacheKeyList) != 0 {
		return true, cacheKeyList
	}
	return false, cacheKeyList
}

func (f *FindCacheKeys) BinarySearchHeaders(target *models.TargetStruct) (bool, []string) {
	var wg sync.WaitGroup
	var headerValues sync.Map
	var search func(target *models.TargetStruct, headers []string)

	search = func(target *models.TargetStruct, headers []string) {
		defer wg.Done()
		if len(headers) == 0 {
			return
		}
		mid := len(headers) / 2
		leftPart := headers[:mid]
		rightPart := headers[mid:]

		tryRequest := func(headers []string) (*http.Response, error) {
			tmpReq, _ := utils.CloneRequest(target.Request)
			hvMap := make(map[string]string, len(headers))
			for _, h := range headers {
				hvMap[h] = utils.RandomString(5)
			}
			return f.GetRespByDefHeader(tmpReq, hvMap, target.Response.StatusCode)
		}

		var resp *http.Response
		var err error
		for range 3 {
			time.Sleep(500 * time.Millisecond)
			resp, err = tryRequest(headers)
			if err == nil && resp != nil && utils.IsCacheHit(target, &resp.Header) {
				return
			}
		}

		if resp != nil {
			defer utils.CloseReader(resp.Body)
			if len(headers) == 1 {
				if resp.StatusCode == target.Response.StatusCode && utils.IsCacheMiss(target, &resp.Header) {
					headerValues.Store(headers[0], utils.RandomString(5))
				}
				return
			}
		}

		wg.Add(2)
		go search(target, leftPart)
		go search(target, rightPart)
	}

	wg.Add(1)
	search(target, f.HeaderWordList)
	wg.Wait()

	var cacheKeyList []string
	headerValues.Range(func(key, value interface{}) bool {
		cacheKeyList = append(cacheKeyList, key.(string))
		return true
	})

	return len(cacheKeyList) != 0, cacheKeyList
}

// GetRespByDefHeader 随机 Header 参数和随机 Value 获取一个响应
func (f *FindCacheKeys) GetRespByDefHeader(req *http.Request, hvMap map[string]string, primitiveRespStatusCOde int) (*http.Response, error) {
	if len(hvMap) == 0 {
		err := fmt.Errorf("hvMap 为空")
		return nil, err
	}
	for k, v := range hvMap {
		req.Header.Set(k, v)
	}
	resp, err := utils.CommonClient.Do(req)
	if err != nil {
		return nil, err
	}
	// 因为有些服务接受不了很长的请求头，会响应一个异常状态码，如果是这种情况的话就响应一个错误，上层调用方需要减小请求头的数量
	if resp.StatusCode != primitiveRespStatusCOde {
		err = fmt.Errorf("the target %s returned an unexpected status code: %d", req.URL, resp.StatusCode)
		return resp, err
	}
	return resp, err
}

// GetRespByDefGetParams 随机 GET 参数和随机 Value 获取一个响应
func (f *FindCacheKeys) GetRespByDefGetParams(req *http.Request, key, value string) (resp *http.Response, err error) {
	// 为当前参数构造一个新的查询字符串
	values := req.URL.Query()
	values.Set(key, value)
	req.URL.RawQuery = values.Encode()
	return utils.CommonClient.Do(req)
}

// GetRespByDefCookie 给cookie 一个随机值，获取响应
func (f *FindCacheKeys) GetRespByDefCookie(req *http.Request, cookie *http.Cookie, value string) (*http.Response, error) {
	cookie.Value = value
	req.AddCookie(cookie)
	resp, err := utils.CommonClient.Do(req)
	return resp, err
}

// FindCacheKeyByCookie 判断cookie 中是否存在缓存键
func (f *FindCacheKeys) FindCacheKeyByCookie(target *models.TargetStruct) (bool, []string) {
	cookies := target.Request.Cookies()
	if len(cookies) == 0 {
		tmpReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return false, nil
		}
		// 随机cookie，判断是否任意cookie都是缓存键
		// 如果任意cookie都是缓存键，那么就没有必要测试cookie是否是缓存破坏者了

		for range 3 {
			cookieName := utils.RandomString(5)
			value := utils.RandomString(5)
			cookie := &http.Cookie{Name: cookieName, Value: value}
			tmpReq.AddCookie(cookie)
			time.Sleep(500 * time.Millisecond)
			resp, err := utils.CommonClient.Do(tmpReq)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return false, nil
			}
			if utils.IsCacheHit(target, &resp.Header) {
				return false, nil
			}
		}
		gologger.Info().Msgf("Target:%s Any cookie is a cache key.", target.Request.URL)
		return false, nil

	}

	cookieCacheKeys := make([]string, 0)
	for _, cookie := range cookies {
		tmpReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return false, nil
		}
		tmpReq.Header.Set("Cookie", "")
		for range 3 {
			value := utils.RandomString(5)
			time.Sleep(500 * time.Millisecond)
			resp, err := f.GetRespByDefCookie(tmpReq, cookie, value)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return false, nil
			}
			if !utils.IsCacheMiss(target, &resp.Header) {
				return false, nil
			}
		}
		gologger.Info().Msgf("Target:%s %s:%s", target.Request.URL, cookie, utils.RandomString(5))
		cookieCacheKeys = append(cookieCacheKeys, cookie.Name)
	}
	if len(cookieCacheKeys) != 0 {
		return true, cookieCacheKeys
	}
	return false, nil
}
