package dos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/pkg/utils"
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

func (h *Hmo) Scan(target *internal.TargetStruct) {
	for _, header := range h.headers {
		for _, value := range h.values {
			resp, err := tecniques.GetResp(target, tecniques.HEADER, map[string]string{header: value})
			if err != nil {
				gologger.Error().Msgf(err.Error())
				return
			}
			if resp.StatusCode != target.Response.StatusCode || resp.ContentLength != target.Response.ContentLength {
				tmpReq1, err := utils.CloneRequest(resp.Request)
				if err != nil {
					gologger.Error().Msgf(err.Error())
					return
				}
				tmpReq2, _ := utils.CloneRequest(resp.Request)
				tmpResp1, _ := utils.CommonClient.Do(tmpReq1)
				tmpResp2, _ := utils.CommonClient.Do(tmpReq2)
				if tmpResp1.StatusCode == tmpResp2.StatusCode || tmpResp1.ContentLength == tmpResp2.ContentLength {
					gologger.Info().Msgf("目标%s 存在CPDOS漏洞，检测技术是HMC", target.Request.URL)
				}
			}
		}
	}
}
