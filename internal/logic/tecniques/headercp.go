package tecniques

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"strings"
	"sync"
)

type HeaderCP struct {
}

var HCPTechniques *HeaderCP

func init() {
	HCPTechniques = NewHeaderCP()
}

func NewHeaderCP() *HeaderCP {
	return &HeaderCP{}
}

func (h *HeaderCP) Scan2(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}
	// 使用WaitGroup来等待所有goroutines完成
	var wg sync.WaitGroup
	// 获取unkeyed headers
	unkeyedHeaders, err := GetUnkeyedHeaders(target)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	var recursionScan func(target *models.TargetStruct, unkeyedHeaders []string)
	recursionScan = func(target *models.TargetStruct, unkeyedHeaders []string) {
		defer wg.Done()
		if len(unkeyedHeaders) == 0 {
			return
		}
		mid := len(unkeyedHeaders) / 2
		// 防止出现意外，陷入死循环
		if mid < 1 {
			return
		}
		leftPart := unkeyedHeaders[:mid]
		rightPart := unkeyedHeaders[mid:]
		payloadMap := make(map[string]string)
		for _, header := range unkeyedHeaders {
			payloadMap[header] = utils.RandomString(5)
		}
		resp, err := GetResp(target, HEADER, payloadMap)
		if err != nil {
			wg.Add(2)
			go recursionScan(target, leftPart)
			go recursionScan(target, rightPart)
			return
		}
		if resp.StatusCode == target.Response.StatusCode {
			respHeaders := resp.Header
			respBodyStr, err := io.ReadAll(resp.Body)
			if err != nil {
				gologger.Error().Msg("CCPTechniques.Scan" + err.Error() + ":")
				return
			}
			utils.CloseReader(resp.Body)
			for k, v := range payloadMap {
				if strings.Contains(string(respBodyStr), "<"+v) {
					gologger.Info().Msgf("The target %s has a non-cache key request header exposed in the response body, potentially indicating a cache poisoning vulnerability. %s: %s.", target.Request.URL, k, v)
				}
				if respHeaders.Get(v) != "" {
					gologger.Info().Msgf("The target %s has a non-cache key request header exposed in the response header, potentially indicating a cache poisoning vulnerability. %s: %s.", target.Request.URL, k, v)
				}
			}
			return
		}
		wg.Add(2)
		go recursionScan(target, leftPart)
		go recursionScan(target, rightPart)
	}
	wg.Add(1)
	go recursionScan(target, unkeyedHeaders)
	wg.Wait()
}

// Scan
// 异常状态码检测,检查XSS和CRLF漏洞
func (h *HeaderCP) Scan(target *models.TargetStruct) {
	var wg sync.WaitGroup
	if target.Cache.NoCache {
		return
	}
	// 获取目标最大支持的请求头数量
	//maxNum := CheckMaxReqHeaderNum(target)
	//if maxNum == 0 {
	//	return
	//}
	//// 将请求头分组
	//groups := GroupSlice(models.Config.Headers, maxNum)
	//if len(groups) == 0 {
	//	return
	//}

	//for _, group := range groups {
	//	wg.Add(1)
	//	go h.findVulnerability(target, group, &wg)
	//}
	wg.Add(1)
	go h.findVulnerability(target, models.Config.Headers, &wg)
	wg.Wait()
}

// CheckMaxReqHeaderNum 检查最大支持的响应头数量
func CheckMaxReqHeaderNum(target *models.TargetStruct) (maxNum int) {
	// 基础请求头数量，1024个
	baseNum := len(models.Config.Headers)
	baseHeaders := GetRandomHeaderAndRandomValue(baseNum)
	for {
		baseNum = baseNum / 2
		if baseNum == 1 {
			return
		}
		tmpReq, err := GetSourceRequestWithCacheKey(target)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		for headerName, value := range baseHeaders {
			tmpReq.Header.Add(headerName, value)
		}
		resp, err := utils.CommonClient.Do(tmpReq)
		if err != nil {
			continue
		}
		if resp.StatusCode == target.Response.StatusCode {
			return baseNum
		}
	}
}

func GetRandomHeaderAndRandomValue(num int) map[string]string {
	headers := make(map[string]string)
	for range num {
		headers[utils.RandomString(5)] = utils.RandomString(5)
	}
	return headers
}

// GroupSlice 切片按照数量分组
func GroupSlice(slice []string, groupSize int) [][]string {
	var groups [][]string
	for i := 0; i < len(slice); i += groupSize {
		end := i + groupSize
		if end > len(slice) {
			end = len(slice)
		}
		groups = append(groups, slice[i:end])
	}
	return groups
}

// findVulnerability 二分法检查是否存在漏洞和异常状态码
func (h *HeaderCP) findVulnerability(target *models.TargetStruct, headers []string, wg *sync.WaitGroup) {
	defer wg.Done()
	pvMap := make(map[string]string)
	for _, header := range headers {
		pvMap[header] = utils.RandomString(5)
	}
	resp, err := GetResp(target, HEADER, pvMap)
	if err != nil {
		return
	}
	defer utils.CloseReader(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	// 如果响应码异常，判断此异常状态是否存在缓存机制，如果存在则缓存投毒漏洞
	if resp.StatusCode != target.Response.StatusCode {
		mid := len(headers) / 2
		leftPart := headers[:mid]
		rightPart := headers[mid:]

		if len(headers) == 1 {
			for range 3 {
				tmpReq, err := utils.CloneRequest(resp.Request)
				if err != nil {
					continue
				}
				tmpResp, err := utils.CommonClient.Do(tmpReq)
				if err != nil {
					continue
				}

				if tmpResp.StatusCode != target.Response.StatusCode && (utils.IsCacheHit(target, &tmpResp.Header) || utils.IsCacheMiss(target, &tmpResp.Header)) {
					gologger.Info().Msgf("The target %s has a non-cache key request header exposed in the response body, potentially indicating a cache poisoning vulnerability. %s", target.Request.URL, pvMap)
					return
				}
			}
			return
		}
		wg.Add(2)
		go h.findVulnerability(target, leftPart, wg)
		go h.findVulnerability(target, rightPart, wg)
	}

	if resp.StatusCode == target.Response.StatusCode {
		// 判断Body中是否存在某些字符串
		for header, value := range pvMap {
			if strings.Contains(string(respBody), "<"+value) {
				gologger.Info().Msgf("The target %s has a non-cache key request header exposed in the response body, potentially indicating a cache poisoning vulnerability. %s: %s.", target.Request.URL, header, utils.RandomString(5))
				break
			}
		}

		for header, value := range pvMap {
			if resp.Header.Get(value) != "" {
				gologger.Info().Msgf("The target %s has a non-cache key request header exposed in the response body, potentially indicating a cache poisoning vulnerability. %s: %s.", target.Request.URL, header, utils.RandomString(5))
				break
			}
		}
		return
	}
}
