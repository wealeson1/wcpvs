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

func (h *HeaderCP) Scan(target *models.TargetStruct) {
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
