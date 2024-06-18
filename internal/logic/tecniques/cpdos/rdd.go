package dos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"strings"
)

type RDD struct {
	payload string
}

func NewRdd() *RDD {
	return &RDD{
		payload: utils.RandomString(2048),
	}
}

func (r *RDD) Scan(target *internal.TargetStruct) {
	primitiveStatusCode := target.Response.StatusCode
	if primitiveStatusCode > 200 && primitiveStatusCode < 300 {
		if !target.Cache.CKIsGet {
			tmpReq, err := utils.CloneRequest(target.Request)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
				return
			}
			randomParam := utils.RandomString(10)
			randomValue := utils.RandomString(10)
			values := tmpReq.URL.Query()
			values.Set(randomParam, randomValue)
			tmpReq.URL.RawQuery = values.Encode()
			resp, err := utils.CommonClient.Do(tmpReq)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
				return
			}
			location := resp.Header.Get("Location")
			if strings.Contains(location, randomParam) {
				gologger.Info().Msgf("目标%s 存在CPDOS漏洞，检测技术是RDD", target.Request.URL)
			}
		}
	}
}
