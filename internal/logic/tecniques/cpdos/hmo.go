package cpdos

import (
	"fmt"
	"io"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"golang.org/x/exp/maps"
)

type Hmo struct {
	values  []string
	headers []string
}

var HMOTecniques *Hmo

func init() {
	HMOTecniques = NewHmo()
}

func NewHmo() *Hmo {
	return &Hmo{
		values:  []string{"GET", "POST", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH", "PUT", "TRACE", "NONSENSE"},
		headers: []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"},
	}
}

func (h *Hmo) Scan(target *models.TargetStruct) {
	payloadMap := make(map[string]string)
	for _, value := range h.values {
		for _, header := range h.headers {
			payloadMap[header] = value
		}
		resp, err := tecniques.GetRespNoPayload(target, tecniques.HEADER, payloadMap)
		if err != nil {
			gologger.Error().Msgf("Hmo.Scan:%s", err.Error())
			return
		}
		utils.CloseReader(resp.Body)
		//respBody, err := io.ReadAll(resp.Body)
		//if err != nil {
		//	gologger.Error().Msgf("Hmo.Scan:%s", err.Error())
		//	return
		//}
		//长度相差大于总体响应的十分之一，视为异常
		//diff := len(target.RespBody) - len(respBody)
		//if diff < 0 {
		//	diff = -diff
		//}
		if resp.StatusCode != target.Response.StatusCode {
			// 情况，偶尔一次的错误会导致状态码异常，但是又不是Payload造成的异常
			// 第二次循环的时候又正常了，并且正常的页面是有缓存机制的，就判定存在漏洞了
			// 预防：响应异常状态码的时候判断下是否存在缓存机制，如果不存在，就继续测试
			//tmpTarget := &models.TargetStruct{
			//	Response: resp,
			//	Cache:    &models.CacheStruct{},
			//}
			//hasCache, _ := logic.Checker.IsCacheAvailable(tmpTarget)
			//if !hasCache {
			//	continue
			//}
			hasCustomHeaders, _ := utils.HasCustomHeaders(resp)
			if !hasCustomHeaders {
				continue
			}
			tmpReq1, err := utils.CloneRequest(resp.Request)
			if err != nil {
				gologger.Error().Msgf("Hmo.Scan:%s", err.Error())
				return
			}
			for range 3 {
				resp2, err := utils.CommonClient.Do(tmpReq1)
				if err != nil {
					gologger.Error().Msgf("Hmo.Scan:%s", err.Error())
					continue
				}
				isHit := utils.IsCacheHit(target, &resp2.Header)
				statusDiff := target.Response.StatusCode != resp2.StatusCode
				resp2Body, _ := io.ReadAll(resp2.Body)
				utils.CloseReader(resp2.Body)
				if isHit && statusDiff {
					// 输出详细报告
					payloadInfo := fmt.Sprintf("Method Override Headers: %v", maps.Keys(payloadMap))
					attackVector := fmt.Sprintf("HTTP Method Override via headers %v causes error", maps.Keys(payloadMap))
					ReportCPDoSVulnerability(target, output.VulnTypeCPDoSHMO, attackVector, resp2, resp2Body, tmpReq1, payloadInfo)
					return
				}
			}
		}
	}
}
