package tecniques

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"strings"
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

func (p *PCPTechniques) Scan2(target *models.TargetStruct) {
	//if target.Cache.NoCache || target.Cache.CKIsAnyGet {
	if target.Cache.NoCache {
		return
	}
	// 判断是否为anyGet
	value := utils.RandomString(10)
	payloadMap := map[string]string{utils.RandomString(10): value}
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

func (p *PCPTechniques) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache && target.Cache.CKIsAnyGet {
		return
	}
	isAntGet, err := p.findVulnerabilityByAnyGet(target)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	if isAntGet {
		return
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go p.findVulnerability(target, models.Config.Parameters, &wg)
}

func (p *PCPTechniques) findVulnerabilityByAnyGet(target *models.TargetStruct) (bool, error) {
	pvMap := map[string]string{utils.RandomString(5): utils.RandomString(5)}
	resp, err := GetResp(target, GET, pvMap)
	if err != nil {
		return false, err
	}
	defer utils.CloseReader(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	for k, v := range pvMap {
		if RespContains2(string(respBody), v, resp.Header) {
			gologger.Info().Msgf("The target %s has any GET parameter reflected in the response, %s=%s, which may indicate a cache poisoning vulnerability.", target.Request.URL, k, v)
			return true, nil
		}
	}
	return false, nil
}

func (p *PCPTechniques) findVulnerability(target *models.TargetStruct, params []string, wg *sync.WaitGroup) {
	defer wg.Done()
	pvMap := make(map[string]string)
	for _, param := range params {
		pvMap[param] = utils.RandomString(7)
	}
	resp, err := GetResp(target, GET, pvMap)
	if err != nil {
		return
	}
	defer utils.CloseReader(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	if resp.StatusCode != target.Response.StatusCode {
		mid := len(params) / 2
		leftPart := params[:mid]
		rightPart := params[mid:]
		if len(params) == 1 {
			for range 3 {
				tmpReq, err := utils.CloneRequest(resp.Request)
				if err != nil {
					continue
				}
				tmpResp, err := utils.CommonClient.Do(tmpReq)
				if err != nil {
					continue
				}
				if tmpResp.StatusCode != target.Response.StatusCode && utils.IsCacheHit(target, &tmpResp.Header) {
					gologger.Info().Msgf("Target %s has cahce-poising vulnerability,tecnique is paeam injection cache poising,%s", target.Request.URL, pvMap)
				}
			}
		}
		wg.Add(2)
		go p.findVulnerability(target, leftPart, wg)
		go p.findVulnerability(target, rightPart, wg)
	}

	if resp.StatusCode == target.Response.StatusCode {
		// 判断Body中是否存在某些字符串
		for param, value := range pvMap {
			if strings.Contains(string(respBody), "<"+value) {
				gologger.Info().Msgf("存在缓存投毒漏洞，paeam's value will be show in respBody,header name is %s:%s", param, utils.RandomString(5))
				break
			}
		}

		for param, value := range pvMap {
			if resp.Header.Get(value) != "" {
				gologger.Info().Msgf("存在缓存投毒漏洞，paeam's value will be show in respBody,header name is %s:%s", param, utils.RandomString(5))
				break
			}
		}
		return
	}
}
