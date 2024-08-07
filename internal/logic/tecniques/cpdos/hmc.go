package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"time"
)

var HMCTecniques *Hmc

type Hmc struct {
	headers []string
	values  []string
}

func init() {
	HMCTecniques = NewHmc()
}

func NewHmc() *Hmc {
	return &Hmc{
		headers: []string{"X-Metachar-Header", "\\n"},
		values:  []string{"\\n", "\\r", "\\a", "\\0", "\\b", "\\e", "\\v", "\\f", "\\u0000"},
	}
}

func (h *Hmc) Scan(target *models.TargetStruct) {
	for _, header := range h.headers {
		for _, value := range h.values {
			time.Sleep(500 * time.Millisecond)
			resp, err := tecniques.GetRespNoPayload(target, tecniques.HEADER, map[string]string{header: value})
			if err != nil {
				continue
			}
			utils.CloseReader(resp.Body)
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
					gologger.Error().Msg(err.Error())
					return
				}
				for range 3 {
					resp2, err := utils.CommonClient.Do(tmpReq1)
					if err != nil {
						gologger.Error().Msgf("Hmc.Scan:%s", err.Error())
						continue
					}

					tmpReq1, err = utils.CloneRequest(resp2.Request)
					if err != nil {
						gologger.Error().Msgf("Hmc.Scan:%s", err.Error())
						continue
					}
					if utils.IsCacheHit(target, &resp2.Header) && target.Response.StatusCode != resp2.StatusCode {
						gologger.Info().Msgf("The target %s has a CPDOS vulnerability, detected using Hmc. %s:%s.", target.Request.URL, header, value)
						return
					}
					utils.CloseReader(resp2.Body)
				}
			}
		}
	}
}
