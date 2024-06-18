package tecniques

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"sync"
)

var ParameterCP *PCPTechniques

type PCPTechniques struct {
}

func NewParameterCP() *PCPTechniques {
	return &PCPTechniques{}
}

func init() {
	ParameterCP = NewParameterCP()
}

func (p *PCPTechniques) Scan(target *models.TargetStruct) {
	//if target.Cache.NoCache || target.Cache.CKIsAnyGet {
	if target.Cache.NoCache {
		return
	}
	// 判断是否为anyGet
	payloadMap := map[string]string{utils.RandomString(10): utils.RandomString(10)}
	resp, err := GetResp(target, GET, payloadMap)
	if err != nil {
		return
	}
	respBody, err := io.ReadAll(resp.Body)
	respHeader := resp.Header
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	for k, v := range payloadMap {
		if RespContains2(string(respBody), k, respHeader) || RespContains2(string(respBody), v, respHeader) {
			gologger.Info().Msgf("The target %s has any GET parameter reflected in the response, %s=%s, which may indicate a cache poisoning vulnerability.", target.Request.URL, k, v)
			target.Cache.AnyGetParamsInResp = true
			return
		}
	}

	var wg sync.WaitGroup
	var recursionScan func(target *models.TargetStruct, parameters []string)
	recursionScan = func(target *models.TargetStruct, parameters []string) {
		defer wg.Done()
		// 检查参数数组是否为空
		if len(parameters) == 0 {
			return
		}
		payloadMap := make(map[string]string)
		for _, parameter := range parameters {
			payloadMap[parameter] = utils.RandomString(5)
		}

		resp2, err := GetResp(target, GET, payloadMap)
		if err != nil {
			return
		}
		respBody, err := io.ReadAll(resp2.Body)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		utils.CloseReader(resp2.Body)
		respHeader := resp2.Header
		if resp2.StatusCode == target.Response.StatusCode {
			for h, v := range payloadMap {
				if RespContains2(string(respBody), v, respHeader) {
					gologger.Info().Msgf("The target %s exhibits GET parameters reflected in the response: %s=%s, suggesting a potential cache poisoning vulnerability.", target.Request.URL, h, v)
					target.Cache.InRespOfGetParams = append(target.Cache.InRespOfGetParams, h)
				}
			}
			return
		}
		mid := len(parameters) / 2
		if mid > 1 {
			leftPart := parameters[:mid]
			rightPart := parameters[mid:]
			wg.Add(2)
			go recursionScan(target, leftPart)
			go recursionScan(target, rightPart)
		}
	}
	wg.Add(1)
	recursionScan(target, models.Config.Parameters)
	wg.Wait()

}
