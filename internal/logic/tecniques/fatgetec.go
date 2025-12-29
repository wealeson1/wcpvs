package tecniques

import (
	"fmt"
	"net/http"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
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
	f.fatGetDosScan(target)

	//tmpReq, err := utils.CloneRequest(target.Request)
	//if target.Cache.CKIsAnyGet {
	//	randomParam := utils.RandomString(5)
	//	randomValue := utils.RandomString(5)
	//	if err != nil {
	//		return
	//	}
	//	tmpReq = utils.AddParam(tmpReq, "GET", randomParam, randomValue)
	//
	//	resp, err := utils.CommonClient.Do(tmpReq)
	//	if err != nil {
	//		gologger.Error().Msg(err.Error())
	//		return
	//	}
	//	defer utils.CloseReader(resp.Body)
	//	respBody, err := io.ReadAll(resp.Body)
	//	if err != nil {
	//		gologger.Error().Msg(err.Error())
	//		return
	//	}
	//	// Get参数会展示到Body里面
	//	if strings.Contains(string(respBody), randomValue) {
	//		tmpReq2, err := utils.CloneRequest(target.Request)
	//		if err != nil {
	//			gologger.Error().Msg(err.Error())
	//			return
	//		}
	//		tmpReq2 = utils.AddParam(tmpReq, "GET", randomParam, utils.RandomString(5))
	//		tmpReq2 = utils.AddParam(tmpReq, "POST", randomParam, randomValue)
	//		resp2, err := utils.CommonClient.Do(tmpReq2)
	//		if err != nil {
	//			gologger.Error().Msg(err.Error())
	//			return
	//		}
	//		defer utils.CloseReader(resp2.Body)
	//		respBody2, err := io.ReadAll(resp2.Body)
	//		if err != nil {
	//			gologger.Error().Msg(err.Error())
	//			return
	//		}
	//		if strings.Contains(string(respBody2), randomValue) {
	//			gologger.Info().Msgf("The target %s has a cache poisoning vulnerability, exploited using the FatGet technique.", target.Request.URL)
	//			return
	//		}
	//	}
	//}
	//
	//if len(target.Cache.InRespOfGetParams) != 0 {
	//	for _, p := range target.Cache.InRespOfGetParams {
	//		randomValue := utils.RandomString(5)
	//		tmpReq := utils.AddParam(tmpReq, "GET", p, utils.RandomString(5))
	//		tmpReq = utils.AddParam(tmpReq, "POST", p, randomValue)
	//
	//		if target.Cache.CKIsAnyGet {
	//			randomParam := utils.RandomString(5)
	//			randomValue := utils.RandomString(5)
	//			values := tmpReq.URL.Query()
	//			values.Set(randomParam, randomValue)
	//			tmpReq.URL.RawQuery = values.Encode()
	//		} else if target.Cache.CKIsHeader {
	//			randomValue := utils.RandomString(5)
	//			tmpReq.Header.Set(target.Cache.HeaderCacheKeys[0], randomValue)
	//		} else if target.Cache.CKisCookie {
	//			randomValue := utils.RandomString(5)
	//			for _, v := range tmpReq.Cookies() {
	//				if strings.EqualFold(v.Name, target.Cache.CookieCacheKeys[0]) {
	//					v.Value = randomValue
	//				}
	//			}
	//		}
	//
	//		resp, err := utils.CommonClient.Do(tmpReq)
	//		if err != nil {
	//			gologger.Error().Msg(err.Error())
	//			return
	//		}
	//		respBody, err := io.ReadAll(resp.Body)
	//		if err != nil {
	//			gologger.Error().Msg(err.Error())
	//			return
	//		}
	//		if strings.Contains(string(respBody), randomValue) {
	//			gologger.Info().Msgf("The target %s has a cache poisoning vulnerability, exploited using the FatGet technique.", target.Request.URL)
	//			return
	//		}
	//	}
	//}
}

func (f *FatGet) fatGetDosScan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}

	// 创建验证器
	verifier := utils.NewPoisoningVerifier()

	// 准备测试参数
	param := utils.RandomString(5)
	value := utils.RandomString(5)

	// 创建攻击请求：GET + POST body
	attackReq, err := GetSourceRequestWithCacheKey(target)
	if err != nil {
		gologger.Error().Msg("fatGetDosScan: " + err.Error())
		return
	}
	attackReq = utils.AddParam(attackReq, "POST", param, value)

	// 创建验证请求：正常GET（不带POST body）
	verifyReq, err := GetSourceRequestWithCacheKey(target)
	if err != nil {
		gologger.Error().Msg("fatGetDosScan: " + err.Error())
		return
	}

	// 使用验证框架验证
	result, err := verifier.Verify(target, attackReq, verifyReq)
	if err != nil {
		gologger.Error().Msgf("fatGetDosScan verification failed: %v", err)
		return
	}

	// 检查是否存在漏洞
	if result.IsVulnerable {
		// 直接使用验证框架保存的body（无需重新请求）
		verifyResp := result.VerifyResp
		respBody := result.VerifyBody

		// 输出详细报告
		f.reportVulnerability(target, param, value, verifyResp, respBody)
		
		gologger.Debug().Msgf("Fat GET poisoning verified in %v (attack: %d, verify: %d, hit: %v)", 
			result.TotalTime, result.AttackStatus, result.VerifyStatus, result.CacheHit)
	}
}

// reportVulnerability 输出FatGet漏洞的详细报告
func (f *FatGet) reportVulnerability(target *models.TargetStruct, param, value string, 
	resp *http.Response, respBody []byte) {
	
	// 构建请求
	testReq, err := GetSourceRequestWithCacheKey(target)
	if err != nil || testReq == nil {
		// Fallback: 使用原始请求
		testReq, _ = utils.CloneRequest(target.Request)
	}
	if testReq != nil {
		testReq = utils.AddParam(testReq, "POST", param, value)
	}
	
	// 提取缓存键
	cacheKeys := []string{}
	if target.Cache.CKIsGet {
		cacheKeys = append(cacheKeys, target.Cache.GetCacheKeys...)
	}
	if target.Cache.CKIsHeader {
		cacheKeys = append(cacheKeys, target.Cache.HeaderCacheKeys...)
	}
	
	// 格式化请求和响应
	reqStr := output.FormatRequestSimple(testReq, fmt.Sprintf("POST body: %s=%s", param, value))
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, "")
	
	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityCritical,
		Type:         output.VulnTypeFatGet,
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: "POST body with GET method causes abnormal cached response",
		Request:      reqStr,
		Response:     respStr,
		Impact:       "HTTP method override allows caching error responses - affects all users (CPDoS)",
		Persistent:   true,
		Remediation: []string{
			"Strictly enforce HTTP method validation",
			"Do not cache responses with unexpected request bodies",
			"Implement proper POST body handling",
			"Add Content-Type validation at CDN level",
		},
	}
	
	report.Print()
}
