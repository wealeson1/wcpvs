package tecniques

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

type CookieCP struct{}

var CCPTechniques *CookieCP

func NewCookieCP() *CookieCP {
	return &CookieCP{}
}
func init() {
	CCPTechniques = NewCookieCP()
}

func (c *CookieCP) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache || len(target.Request.Cookies()) == 0 {
		return
	}

	primitiveCookies := target.Request.Cookies()
	for _, cookie := range primitiveCookies {
		tmpReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			gologger.Error().Msg("CCPTechniques.Scan" + err.Error())
		}
		tmpReq.Header.Set("Cookie", "")
		randomValue := utils.RandomString(5)
		resp, err := GetResp(target, COOKIE, map[string]string{cookie.Name: randomValue})
		if err != nil {
			gologger.Error().Msg("CCPTechniques.Scan " + err.Error())
			continue
		}
		if RespContains(resp, "<"+randomValue) {
			gologger.Info().Msgf("The target %s has a cookie that is exposed in the response. Cookie: %s:%s. This may indicate a potential cache poisoning vulnerability.", target.Request.URL, cookie.Name, randomValue)
		}
	}
}
