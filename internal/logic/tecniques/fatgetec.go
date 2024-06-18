package tecniques

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"strings"
)

type FatGet struct {
}

var FatGetTechniques *FatGet

func init() {
	FatGetTechniques = NewFatGet()
}
func NewFatGet() *FatGet {
	return &FatGet{}
}

func (f *FatGet) Scan(target *models.TargetStruct) {

	tmpReq, err := utils.CloneRequest(target.Request)
	if target.Cache.CKIsAnyGet {
		randomParam := utils.RandomString(5)
		randomValue := utils.RandomString(5)
		if err != nil {
			return
		}
		tmpReq = utils.AddParam(tmpReq, "GET", randomParam, randomValue)

		resp, err := utils.CommonClient.Do(tmpReq)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		defer utils.CloseReader(resp.Body)
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		// Get参数会展示到Body里面
		if strings.Contains(string(respBody), randomValue) {
			tmpReq2, err := utils.CloneRequest(target.Request)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			tmpReq2 = utils.AddParam(tmpReq, "GET", randomParam, utils.RandomString(5))
			tmpReq2 = utils.AddParam(tmpReq, "POST", randomParam, randomValue)
			resp2, err := utils.CommonClient.Do(tmpReq2)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			defer utils.CloseReader(resp2.Body)
			respBody2, err := io.ReadAll(resp2.Body)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			if strings.Contains(string(respBody2), randomValue) {
				gologger.Info().Msgf("The target %s has a cache poisoning vulnerability, exploited using the FatGet technique.", target.Request.URL)
				return
			}
		}
	}

	if len(target.Cache.InRespOfGetParams) != 0 {
		for _, p := range target.Cache.InRespOfGetParams {
			randomValue := utils.RandomString(5)
			tmpReq := utils.AddParam(tmpReq, "GET", p, utils.RandomString(5))
			tmpReq = utils.AddParam(tmpReq, "POST", p, randomValue)

			if target.Cache.CKIsAnyGet {
				randomParam := utils.RandomString(5)
				randomValue := utils.RandomString(5)
				values := tmpReq.URL.Query()
				values.Set(randomParam, randomValue)
				tmpReq.URL.RawQuery = values.Encode()
			} else if target.Cache.CKIsHeader {
				randomValue := utils.RandomString(5)
				tmpReq.Header.Set(target.Cache.HeaderCacheKeys[0], randomValue)
			} else if target.Cache.CKisCookie {
				randomValue := utils.RandomString(5)
				for _, v := range tmpReq.Cookies() {
					if strings.EqualFold(v.Name, target.Cache.CookieCacheKeys[0]) {
						v.Value = randomValue
					}
				}
			}

			resp, err := utils.CommonClient.Do(tmpReq)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			if strings.Contains(string(respBody), randomValue) {
				gologger.Info().Msgf("The target %s has a cache poisoning vulnerability, exploited using the FatGet technique.", target.Request.URL)
				return
			}
		}
	}
}
