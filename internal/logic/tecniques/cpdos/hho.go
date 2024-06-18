package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
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
	mixSize := 20480

	for headerSize <= mixSize {
		if target.Cache.CKIsAnyGet {
			randomHeader := utils.RandomString(5)
			resp, err := tecniques.GetResp(target, tecniques.HEADER, map[string]string{randomHeader: utils.RandomString(headerSize)})
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			utils.CloseReader(resp.Body)
			if resp.StatusCode != target.Response.StatusCode {
				for range 3 {
					time.Sleep(400 * time.Millisecond)
					tmpReq, err := utils.CloneRequest(resp.Request)
					if err != nil {
						gologger.Error().Msg(err.Error())
						return
					}
					resp, err := utils.CommonClient.Do(tmpReq)
					if err != nil {
						gologger.Error().Msg(err.Error())
						return
					}
					if utils.IsCacheHit(target, &resp.Header) {
						gologger.Info().Msgf("\nThe target %s has a CPDOS vulnerability, detected using HHO. Test: AAAAA...%d.\n", target.Request.URL, headerSize)
						return
					}
					utils.CloseReader(resp.Body)
				}
				return
			}
		}
		if !target.Cache.CKIsAnyGet && target.Cache.CKIsHeader {
			randomParam := utils.RandomString(5)
			resp, err := tecniques.GetResp(target, tecniques.GET, map[string]string{randomParam: utils.RandomString(headerSize)})
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			if resp.StatusCode != target.Response.StatusCode {
				for range 3 {
					tmpReq, err := utils.CloneRequest(resp.Request)
					if err != nil {
						gologger.Error().Msg(err.Error())
						return
					}
					resp, err := utils.CommonClient.Do(tmpReq)
					if err == nil {
						if utils.IsCacheHit(target, &resp.Header) {
							gologger.Info().Msgf("\nThe target %s has a CPDOS vulnerability, detected using HHO. Test: AAAAA...%d.\n", target.Request.URL, headerSize)
							return
						}
					}
				}
			}
		}
		headerSize = headerSize + 1024
	}

}
