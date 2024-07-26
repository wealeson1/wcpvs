package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
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
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msgf("Hmo.Scan:%s", err.Error())
			return
		}
		//长度相差大于总体响应的十分之一，视为异常
		diff := len(target.RespBody) - len(respBody)
		if diff < 0 {
			diff = -diff
		}
		//|| diff > (len(target.RespBody)/3)
		if resp.StatusCode != target.Response.StatusCode {
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
				if utils.IsCacheHit(target, &resp2.Header) {
					gologger.Info().Msgf("The target %s has a CPDOS vulnerability, detected using HMO and %v.", target.Request.URL, payloadMap)
					return
				}
			}
		}
	}
}
