package tecniques

import (
	"errors"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const (
	GET    int = 0
	HEADER int = 1
	COOKIE int = 2
)

// GetResp 根据 target 获取一个回源响应，请求中可以插入用户想插入的任何非缓存键的值
// todo 重复代码拆分
func GetResp(target *models.TargetStruct, position int, pvMap map[string]string) (*http.Response, error) {
	if len(pvMap) == 0 {
		return nil, errors.New("param or value is empty")
	}

	tmpReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		return nil, err
	}
	switch position {
	case GET:
		values := url.Values{}
		for k, v := range pvMap {
			if k == "" {
				continue
			}
			values.Set(k, "<"+v+"\">"+"%0d%0a"+v+":"+v)
		}
		tmpReq.URL.RawQuery = values.Encode()

		if target.Cache.CKIsHeader {
			randomValue := utils.RandomString(5)
			tmpReq.Header.Set(target.Cache.HeaderCacheKeys[0], randomValue)
		} else if target.Cache.CKisCookie {
			randomValue := utils.RandomString(5)
			for _, v := range tmpReq.Cookies() {
				if strings.EqualFold(v.Name, target.Cache.CookieCacheKeys[0]) {
					v.Value = randomValue
				}
			}
		} else {
			err := fmt.Errorf("the target %s has no cache key", target.Request.URL)
			return nil, err
		}
	case HEADER:
		for k, v := range pvMap {
			if target.Cache.CKIsHeader && slices.Contains(target.Cache.HeaderCacheKeys, k) {
				gologger.Warning().Msgf("Header %s is cache key", k)
				continue
			}
			tmpReq.Header.Set(k, "<"+v+"\">"+"%0d%0a"+v+"%3a"+v)
		}
		if target.Cache.CKIsAnyGet {
			randomParam := utils.RandomString(5)
			randomValue := utils.RandomString(5)
			values := tmpReq.URL.Query()
			values.Set(randomParam, randomValue)
			tmpReq.URL.RawQuery = values.Encode()
		} else if target.Cache.CKIsHeader {
			randomValue := utils.RandomString(5)
			tmpReq.Header.Set(target.Cache.HeaderCacheKeys[0], randomValue)
		} else if target.Cache.CKisCookie {
			randomValue := utils.RandomString(5)
			for _, v := range tmpReq.Cookies() {
				if strings.EqualFold(v.Name, target.Cache.CookieCacheKeys[0]) {
					v.Value = randomValue
				}
			}
		} else {
			err := fmt.Errorf("the target %s has no cache key", target.Request.URL)
			return nil, err
		}
	case COOKIE:
		for k, v := range pvMap {
			if target.Cache.CKisCookie && slices.Contains(target.Cache.CookieCacheKeys, k) {
				gologger.Warning().Msgf("Cookie %s is cache key", k)
				continue
			}
			tmpReq.AddCookie(&http.Cookie{Name: k, Value: "<" + v + "%22>" + "%0d%0a" + v + ":" + v})
			if target.Cache.CKIsAnyGet {
				randomParam := utils.RandomString(5)
				randomValue := utils.RandomString(5)
				values := tmpReq.URL.Query()
				values.Set(randomParam, randomValue)
				tmpReq.URL.RawQuery = values.Encode()
			} else if target.Cache.CKIsHeader {
				randomValue := utils.RandomString(5)
				tmpReq.Header.Set(target.Cache.HeaderCacheKeys[0], randomValue)
			} else if target.Cache.CKisCookie {
				randomValue := utils.RandomString(5)
				for _, v := range tmpReq.Cookies() {
					if strings.EqualFold(v.Name, target.Cache.CookieCacheKeys[0]) {
						v.Value = randomValue
					}
				}
			} else {
				err := fmt.Errorf("the target %s has no cache key", target.Request.URL)
				return nil, err
			}
		}
	}
	resp, err := utils.CommonClient.Do(tmpReq)
	return resp, err
}

// GetSourceRequestWithCacheKey 存在缓存键的前提下，获取一个可以回源的request
func GetSourceRequestWithCacheKey(target *models.TargetStruct) (req *http.Request, err error) {
	tmpReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		gologger.Error().Msg("logic.common.GetSourceRequestWithCacheKey:" + err.Error())
		return nil, err
	}
	if target.Cache.CKIsAnyGet {
		randomParam := utils.RandomString(5)
		randomValue := utils.RandomString(5)
		values := tmpReq.URL.Query()
		values.Set(randomParam, randomValue)
		tmpReq.URL.RawQuery = values.Encode()
		return tmpReq, nil
	}

	if target.Cache.CKIsHeader {
		randomValue := utils.RandomString(5)
		tmpReq.Header.Set(target.Cache.HeaderCacheKeys[0], randomValue)
		return tmpReq, nil
	}

	if target.Cache.CKisCookie {
		randomValue := utils.RandomString(5)
		for _, v := range tmpReq.Cookies() {
			if strings.EqualFold(v.Name, target.Cache.CookieCacheKeys[0]) {
				v.Value = randomValue
			}
		}
		return tmpReq, nil
	} else {
		err := fmt.Errorf("the target %s has no cache key", target.Request.URL)
		return nil, err
	}
}

// GetUnkeyedHeaders 删除 header list 中的 target.Cache.HeaderCacheKeys
func GetUnkeyedHeaders(target *models.TargetStruct) ([]string, error) {
	if !target.Cache.CKIsHeader || len(target.Cache.HeaderCacheKeys) == 0 {
		return models.Config.Headers, nil
	}
	unkeyedHeaders := make([]string, 0)
	for _, v := range models.Config.Headers {
		if !slices.Contains(target.Cache.HeaderCacheKeys, strings.ToLower(v)) {
			unkeyedHeaders = append(unkeyedHeaders, v)
		}
	}
	return unkeyedHeaders, nil
}

// RespContains 判断响应中时候包含某字符串
func RespContains(resp *http.Response, substr string) bool {
	defer utils.CloseReader(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return false
	}
	if strings.Contains(string(respBody), substr) {
		return true
	}
	for header := range resp.Header {
		value := resp.Header.Get(header)
		if strings.Contains(value, substr) || strings.Contains(header, substr) {
			return true
		}
	}
	return false
}

// RespContains2 判断响应中时候包含某字符串
func RespContains2(respStr, substr string, headers http.Header) bool {
	if strings.Contains(respStr, "<"+substr) {
		return true
	}
	if headers.Get(substr) != "" {
		return true
	}
	return false
}
