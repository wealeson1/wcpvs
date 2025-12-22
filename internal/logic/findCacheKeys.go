package logic

import (
	"net/http"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

type FindCacheKeys struct {
	HeaderWordList []string
	mu             sync.Mutex // 保护并发写入
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
		return nil
	}

	cacheKeyIsAnyGet, err := f.FindCacheKeyByAnyGet(target)
	if cacheKeyIsAnyGet {
		gologger.Info().Msgf("The target %s treats all GET parameters as cache keys.", target.Request.URL)
		target.Cache.CKIsAnyGet = true
	}

	if err == nil && !cacheKeyIsAnyGet {
		f.FindCacheKeyByGet(target)
		if target.Cache.CKIsGet {
			gologger.Info().Msgf("The target %s has  Get paramters as cache key(s): %v", target.Request.URL, target.Cache.GetCacheKeys)
			target.Cache.CKIsGet = true
		}
	}

	if f.FindCacheKeyByHeader(target) {
		gologger.Info().Msgf("The target %s has request header cache key(s): %v.", target.Request.URL, target.Cache.HeaderCacheKeys)
	}
	//gologger.Info().Msg("Header 缓存键检查结束")

	if target.Cache.CKIsAnyGet || target.Cache.CKIsHeader {
		resp, err := tecniques.GetResp(target, tecniques.COOKIE, map[string]string{utils.RandomString(5): utils.RandomString(5)})
		if err != nil {
			return err
		}
		defer utils.CloseReader(resp.Body)

		// 使用标准的Cookie解析方法
		for _, cookie := range resp.Cookies() {
			if cookie.Name != "" && cookie.Value != "" {
				target.Request.AddCookie(&http.Cookie{
					Name:  cookie.Name,
					Value: cookie.Value,
				})
			}
		}
	}
	if ic, cookies := f.FindCacheKeyByCookie(target); ic && len(cookies) != 0 {
		gologger.Info().Msgf("The target %s has a cookie cache key: %v.", target.Request.URL, cookies)
		target.Cache.CKisCookie = true
		target.Cache.CookieCacheKeys = cookies
	}

	if !target.Cache.CKIsAnyGet && !target.Cache.CKIsHeader && !target.Cache.CKisCookie && !target.Cache.CKIsGet {
		target.Cache.NoCache = true
	}
	return nil
}

// FindCacheKeyByAnyGet 判断是缓存机制是否忽略GET
func (f *FindCacheKeys) FindCacheKeyByAnyGet(target *models.TargetStruct) (bool, error) {
	if len(target.Cache.Indicators) == 0 || target.Cache.NoCache {
		return false, nil
	}

	paramName := utils.RandomString(5)
	paramValue := utils.RandomString(5)
	var tmpResp *http.Response
	var err2 error

	// 第一次请求：每次重试都重新克隆
	for range 3 {
		tmpRequest, err := utils.CloneRequest(target.Request)
		if err != nil {
			gologger.Error().Msgf("FindCacheKeyByAnyGet: %v", err)
			continue
		}
		tmpResp, err2 = f.GetRespByDefGetParams(tmpRequest, paramName, paramValue)
		if err2 == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err2 != nil {
		gologger.Error().Msg(err2.Error())
		return false, err2
	}
	if tmpResp == nil {
		return false, nil
	}
	defer utils.CloseReader(tmpResp.Body)

	if utils.IsCacheMiss(target, &tmpResp.Header) {
		time.Sleep(2000 * time.Millisecond)

		// 重试验证：每次都重新克隆请求
		for range 5 {
			tmpRequest2, err := utils.CloneRequest(target.Request)
			if err != nil {
				gologger.Error().Msgf("FindCacheKeyByAnyGet: %v", err)
				continue
			}
			tmpResp2, err2 := f.GetRespByDefGetParams(tmpRequest2, paramName, paramValue)
			if err2 != nil {
				gologger.Error().Msgf("FindCacheKeyByAnyGet: %v", err2)
				time.Sleep(500 * time.Millisecond)
				continue
			}
			utils.CloseReader(tmpResp2.Body)
			if utils.IsCacheHit(target, &tmpResp2.Header) {
				return true, nil
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	return false, nil
}

//func (f *FindCacheKeys) BinarySearchHeaders(target *models.TargetStruct) (bool, []string) {
//	var wg sync.WaitGroup
//	var headerValues sync.Map
//	var search func(target *models.TargetStruct, headers []string)
//
//	search = func(target *models.TargetStruct, headers []string) {
//		defer wg.Done()
//		if len(headers) == 0 {
//			return
//		}
//		mid := len(headers) / 2
//		leftPart := headers[:mid]
//		rightPart := headers[mid:]
//
//		tryRequest := func(headers []string) (*http.Response, error) {
//			tmpReq, err := utils.CloneRequest(target.Request)
//			if err != nil {
//				return nil, err
//			}
//			hvMap := make(map[string]string, len(headers))
//			for _, h := range headers {
//				hvMap[h] = utils.RandomString(5)
//			}
//			return f.GetRespByDefHeader(tmpReq, hvMap, target.Response.StatusCode)
//		}
//
//		var resp *http.Response
//		var err error
//		resp, err = tryRequest(headers)
//		// 异常状态码 未命中缓存不能直接丢弃，只有当发起请求错误，或者状态码正常且命中缓存的请求丢弃
//		if err != nil || (resp.StatusCode == target.Response.StatusCode && utils.IsCacheHit(target, &resp.Header)) {
//			return
//		}
//		utils.CloseReader(resp.Body)
//		if len(headers) == 1 {
//			if utils.IsCacheMiss(target, &resp.Header) {
//				resp2, err := utils.CommonClient.Do(resp.Request)
//				if err != nil {
//					return
//				}
//				if utils.IsCacheHit(target, &resp2.Header) {
//					headerValues.Store(headers[0], utils.RandomString(5))
//				}
//			}
//			return
//		}
//		wg.Add(2)
//		go search(target, leftPart)
//		go search(target, rightPart)
//	}
//
//	wg.Add(1)
//	search(target, f.HeaderWordList)
//	wg.Wait()
//
//	var cacheKeyList []string
//	headerValues.Range(func(key, value interface{}) bool {
//		cacheKeyList = append(cacheKeyList, key.(string))
//		return true
//	})
//	return len(cacheKeyList) != 0, cacheKeyList
//}

// FindCacheKeyByHeader 寻找请求头缓存键
func (f *FindCacheKeys) FindCacheKeyByHeader(target *models.TargetStruct) bool {
	var wg sync.WaitGroup
	headers := models.Config.Headers
	wg.Add(1)
	go f.BinarySearchHeaders(target, headers, &wg)
	wg.Wait()
	if target.Cache.CKIsHeader {
		return true
	}
	return false
}

// BinarySearchHeaders 二分法搜索 Header 缓存键
func (f *FindCacheKeys) BinarySearchHeaders(target *models.TargetStruct, params []string, wg *sync.WaitGroup) {
	defer wg.Done()

	// 基础情况：没有参数
	if len(params) == 0 {
		return
	}

	// 基础情况：只有一个header，直接测试
	if len(params) == 1 {
		f.testSingleHeader(target, params[0])
		return
	}

	// 克隆请求并添加所有待测试的headers
	tmpRequest, err := utils.CloneRequest(target.Request)
	if err != nil {
		gologger.Error().Msgf("BinarySearchHeaders: failed to clone request: %v", err)
		return
	}

	for _, h := range params {
		tmpRequest.Header.Add(h, utils.RandomString(5))
	}

	tmpResp, err := utils.CommonClient.Do(tmpRequest)
	if err != nil {
		// 如果请求失败，分治递归
		if len(params) > 1 {
			mid := len(params) / 2
			wg.Add(2)
			go f.BinarySearchHeaders(target, params[:mid], wg)
			go f.BinarySearchHeaders(target, params[mid:], wg)
		}
		return
	}
	defer utils.CloseReader(tmpResp.Body)

	// 如果状态码正常且命中缓存，说明这些headers都不影响缓存
	if tmpResp.StatusCode == target.Response.StatusCode && utils.IsCacheHit(target, &tmpResp.Header) {
		return
	}

	// 否则，二分递归查找具体是哪个header
	mid := len(params) / 2
	wg.Add(2)
	go f.BinarySearchHeaders(target, params[:mid], wg)
	go f.BinarySearchHeaders(target, params[mid:], wg)
}

// testSingleHeader 测试单个header是否是缓存键
func (f *FindCacheKeys) testSingleHeader(target *models.TargetStruct, header string) {
	tmpReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		return
	}

	tmpReq.Header.Set(header, utils.RandomString(8))
	tmpResp, err := utils.CommonClient.Do(tmpReq)
	if err != nil {
		return
	}
	defer utils.CloseReader(tmpResp.Body)

	// 如果未命中缓存，等待并重试确认
	if utils.IsCacheMiss(target, &tmpResp.Header) {
		time.Sleep(1 * time.Second)

		for i := 0; i < 3; i++ {
			retryReq, err := utils.CloneRequest(tmpResp.Request)
			if err != nil {
				continue
			}

			retryResp, err := utils.CommonClient.Do(retryReq)
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			utils.CloseReader(retryResp.Body)

			if utils.IsCacheHit(target, &retryResp.Header) {
				// 找到一个header缓存键，需要加锁保护并发写入
				f.mu.Lock()
				target.Cache.CKIsHeader = true
				target.Cache.HeaderCacheKeys = append(target.Cache.HeaderCacheKeys, header)
				f.mu.Unlock()
				gologger.Debug().Msgf("Found header cache key: %s", header)
				return
			}

			time.Sleep(500 * time.Millisecond)
		}
	}
}

// GetRespByDefHeader 随机 Header 参数和随机 Value 获取一个响应
//func (f *FindCacheKeys) GetRespByDefHeader(req *http.Request, hvMap map[string]string, primitiveRespStatusCOde int) (*http.Response, error) {
//	if len(hvMap) == 0 {
//		err := fmt.Errorf("hvMap 为空")
//		return nil, err
//	}
//	for k, v := range hvMap {
//		req.Header.Set(k, v)
//	}
//	return utils.CommonClient.Do(req)
//}

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
	// 创建新的cookie对象，避免修改原对象
	newCookie := &http.Cookie{
		Name:  cookie.Name,
		Value: value,
	}
	req.AddCookie(newCookie)
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
		cookieName := utils.RandomString(5)
		value := utils.RandomString(5)
		cookie := &http.Cookie{Name: cookieName, Value: value}
		tmpReq.AddCookie(cookie)
		resp, err := utils.CommonClient.Do(tmpReq)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return false, nil
		}
		utils.CloseReader(resp.Body)
		if utils.IsCacheMiss(target, &resp.Header) {
			resp2, err := utils.CommonClient.Do(resp.Request)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return false, nil
			}
			isHit := utils.IsCacheHit(target, &resp2.Header)
			utils.CloseReader(resp2.Body)
			if isHit {
				gologger.Info().Msgf("Target:%s Any cookie is a cache key.", target.Request.URL)
				return false, nil
			}
		}
	}

	cookieCacheKeys := make([]string, 0)
	for _, cookie := range cookies {
		tmpReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return false, nil
		}
		tmpReq.Header.Set("Cookie", "")
		value := utils.RandomString(5)
		resp, err := f.GetRespByDefCookie(tmpReq, cookie, value)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return false, nil
		}
		utils.CloseReader(resp.Body)
		if utils.IsCacheMiss(target, &resp.Header) {
			resp2, err := utils.CommonClient.Do(resp.Request)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return false, nil
			}
			isHit := utils.IsCacheHit(target, &resp2.Header)
			utils.CloseReader(resp2.Body)
			if isHit {
				gologger.Info().Msgf("Target:%s %s:%s", target.Request.URL, cookie, utils.RandomString(5))
				cookieCacheKeys = append(cookieCacheKeys, cookie.Name)
			}
		}
	}
	if len(cookieCacheKeys) != 0 {
		return true, cookieCacheKeys
	}
	return false, nil
}

// FindCacheKeyByGet 当时ANY GET不是缓存键时
func (f *FindCacheKeys) FindCacheKeyByGet(target *models.TargetStruct) {
	var wg sync.WaitGroup
	paramsSlice := models.Config.Parameters

	wg.Add(1)
	go f.BinarySearchGetCacheKey(target, paramsSlice, &wg)
	wg.Wait()
}

func (f *FindCacheKeys) BinarySearchGetCacheKey(target *models.TargetStruct, params []string, wg *sync.WaitGroup) {
	defer wg.Done()

	// 基础情况：没有参数
	if len(params) == 0 {
		return
	}

	// 基础情况：只有一个参数，直接测试
	if len(params) == 1 {
		f.testSingleGetParam(target, params[0])
		return
	}

	// 克隆请求并添加所有待测试的GET参数
	tmpReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		gologger.Error().Msgf("BinarySearchGetCacheKey: failed to clone request: %v", err)
		return
	}

	query := tmpReq.URL.Query()
	for _, p := range params {
		query.Add(p, utils.RandomString(5))
	}
	tmpReq.URL.RawQuery = query.Encode()

	tmpResp, err := utils.CommonClient.Do(tmpReq)
	if err != nil {
		// 如果请求失败，分治递归
		if len(params) > 1 {
			mid := len(params) / 2
			wg.Add(2)
			f.BinarySearchGetCacheKey(target, params[:mid], wg)
			f.BinarySearchGetCacheKey(target, params[mid:], wg)
		}
		return
	}
	defer utils.CloseReader(tmpResp.Body)

	// 如果状态码正常且命中缓存，说明这些参数都不影响缓存
	if tmpResp.StatusCode == target.Response.StatusCode && utils.IsCacheHit(target, &tmpResp.Header) {
		return
	}

	// 否则，二分递归查找具体是哪个参数
	mid := len(params) / 2
	wg.Add(2)
	f.BinarySearchGetCacheKey(target, params[:mid], wg)
	f.BinarySearchGetCacheKey(target, params[mid:], wg)
}

// testSingleGetParam 测试单个GET参数是否是缓存键
func (f *FindCacheKeys) testSingleGetParam(target *models.TargetStruct, param string) {
	tmpReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		return
	}

	query := tmpReq.URL.Query()
	query.Add(param, utils.RandomString(8))
	tmpReq.URL.RawQuery = query.Encode()

	tmpResp, err := utils.CommonClient.Do(tmpReq)
	if err != nil {
		return
	}
	defer utils.CloseReader(tmpResp.Body)

	// 如果未命中缓存，等待并重试确认
	if utils.IsCacheMiss(target, &tmpResp.Header) {
		time.Sleep(1 * time.Second)

		for i := 0; i < 3; i++ {
			retryReq, err := utils.CloneRequest(tmpResp.Request)
			if err != nil {
				continue
			}

			retryResp, err := utils.CommonClient.Do(retryReq)
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			utils.CloseReader(retryResp.Body)

			if utils.IsCacheHit(target, &retryResp.Header) {
				// 找到一个GET参数缓存键，加锁保护并发写入
				f.mu.Lock()
				target.Cache.CKIsGet = true
				target.Cache.GetCacheKeys = append(target.Cache.GetCacheKeys, param)
				f.mu.Unlock()
				gologger.Debug().Msgf("Found GET param cache key: %s", param)
				return
			}

			time.Sleep(500 * time.Millisecond)
		}
	}
}
