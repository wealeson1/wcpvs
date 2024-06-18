package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
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

func (h *Hmo) Scan(target *models.TargetStruct) {
	payloadMap := make(map[string]string)
	for _, value := range h.values {
		for _, header := range h.headers {
			payloadMap[header] = value
		}
		resp, err := tecniques.GetResp(target, tecniques.HEADER, payloadMap)
		if err != nil {
			gologger.Error().Msgf(err.Error())
			return
		}
		//长度相差大于10
		//diff := math.Abs(float64(resp.ContentLength - target.Response.ContentLength))
		// 有时候某些站点会有一些意外情况
		if resp.StatusCode != target.Response.StatusCode {
			tmpReq1, err := utils.CloneRequest(resp.Request)
			if err != nil {
				gologger.Error().Msgf(err.Error())
				return
			}
			for range 3 {
				resp, err := utils.CommonClient.Do(tmpReq1)
				if err != nil {
					continue
				}
				if utils.IsCacheHit(target, &resp.Header) {
					gologger.Info().Msgf("\nThe target %s has a CPDOS vulnerability, detected using HMO and %v.\n", target.Request.URL, payloadMap)
					return
				}
			}
		}
	}
}
