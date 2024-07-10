package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"strings"
)

var LRDTecniques *LRD

type LRD struct {
}

func NewRdd() *LRD {
	return &LRD{}
}

func init() {
	LRDTecniques = NewRdd()
}

func (r *LRD) Scan(target *models.TargetStruct) {
	primitiveStatusCode := target.Response.StatusCode
	if primitiveStatusCode > 300 && primitiveStatusCode < 400 {
		if !target.Cache.CKIsAnyGet {
			tmpReq, err := utils.CloneRequest(target.Request)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
				return
			}
			randomParam := utils.RandomString(5)
			randomValue := utils.RandomString(5)
			values := tmpReq.URL.Query()
			values.Set(randomParam, randomValue)
			tmpReq.URL.RawQuery = values.Encode()
			pvMap := map[string]string{
				randomParam: randomValue,
			}
			resp, err := tecniques.GetResp(target, tecniques.GET, pvMap)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
				return
			}
			location := resp.Header.Get("Location")
			if strings.Contains(location, randomParam) {
				gologger.Info().Msgf("The target %s has a CPDOS vulnerability, detected using RDD.", target.Request.URL)
				return
			}
		}
	}
}
