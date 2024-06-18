package dos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/pkg/utils"
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
		headers: []string{"X-Metachar-Header"},
		values:  []string{"\\n", "\\r", "\\a", "\\0", "\\b", "\\e", "\\v", "\\f", "\\u0000"},
	}
}

func (h *Hmc) Scan(target *internal.TargetStruct) {
	for _, header := range h.headers {
		for _, value := range h.values {
			resp, err := tecniques.GetResp(target, tecniques.HEADER, map[string]string{header: value})
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			if resp.StatusCode != target.Response.StatusCode {
				tmpReq1, err := utils.CloneRequest(resp.Request)
				if err != nil {
					gologger.Error().Msg(err.Error())
					return
				}
				tmpReq2, _ := utils.CloneRequest(tmpReq1)
				tmpResp1, err := utils.CommonClient.Do(tmpReq1)
				if err != nil {
					gologger.Error().Msg(err.Error())
					return
				}
				tmpResp2, _ := utils.CommonClient.Do(tmpReq2)
				if tmpResp1.StatusCode == tmpResp2.StatusCode {
					gologger.Info().Msgf("目标%s 存在CPDOS漏洞，检测技术是Hmc", target.Request.URL)
				}
			}
		}
	}
}
