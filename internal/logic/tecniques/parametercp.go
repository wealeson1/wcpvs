package tecniques

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"golang.org/x/exp/maps"
)

var ParameterCP *PCPTechniques

type PCPTechniques struct {
	PcpParams       map[string][]string
	RWLock          sync.RWMutex
	VulnParams      map[string][]VulnParam // 收集每个URL的所有漏洞参数
	VulnParamsMutex sync.Mutex
}

type VulnParam struct {
	Param      string
	StatusCode int
	VulnType   string
}

func NewParameterCP() *PCPTechniques {
	return &PCPTechniques{
		PcpParams:       make(map[string][]string),
		RWLock:          sync.RWMutex{},
		VulnParams:      make(map[string][]VulnParam),
		VulnParamsMutex: sync.Mutex{},
	}
}

func init() {
	ParameterCP = NewParameterCP()
}

//func (p *PCPTechniques) Scan2(target *models.TargetStruct) {
//	//if target.Cache.NoCache || target.Cache.CKIsAnyGet {
//	if target.Cache.NoCache {
//		return
//	}
//	// 判断是否为anyGet
//	value := utils.RandomString(10)
//	payloadMap := map[string]string{utils.RandomString(10): value}
//	resp, err := GetResp(target, GET, payloadMap)
//	if err != nil {
//		return
//	}
//	respBody, err := io.ReadAll(resp.Body)
//	respHeader := resp.Header
//	if err != nil {
//		gologger.Error().Msg(err.Error())
//		return
//	}
//	for k, v := range payloadMap {
//		if RespContains2(string(respBody), k, respHeader) || RespContains2(string(respBody), v, respHeader) {
//			gologger.Info().Msgf("The target %s has any GET parameter reflected in the response, %s=%s, which may indicate a cache poisoning vulnerability.", target.Request.URL, k, v)
//			target.Cache.AnyGetParamsInResp = true
//			return
//		}
//	}
//
//	var wg sync.WaitGroup
//	var recursionScan func(target *models.TargetStruct, parameters []string)
//	recursionScan = func(target *models.TargetStruct, parameters []string) {
//		defer wg.Done()
//		// 检查参数数组是否为空
//		if len(parameters) == 0 {
//			return
//		}
//		payloadMap := make(map[string]string)
//		for _, parameter := range parameters {
//			payloadMap[parameter] = utils.RandomString(5)
//		}
//
//		resp2, err := GetResp(target, GET, payloadMap)
//		if err != nil {
//			return
//		}
//		respBody, err := io.ReadAll(resp2.Body)
//		if err != nil {
//			gologger.Error().Msg(err.Error())
//			return
//		}
//		utils.CloseReader(resp2.Body)
//		respHeader := resp2.Header
//		if resp2.StatusCode == target.Response.StatusCode {
//			for h, v := range payloadMap {
//				if RespContains2(string(respBody), v, respHeader) {
//					gologger.Info().Msgf("The target %s exhibits GET parameters reflected in the response: %s=%s, suggesting a potential cache poisoning vulnerability.", target.Request.URL, h, v)
//					target.Cache.InRespOfGetParams = append(target.Cache.InRespOfGetParams, h)
//				}
//			}
//			return
//		}
//		mid := len(parameters) / 2
//		if mid > 1 {
//			leftPart := parameters[:mid]
//			rightPart := parameters[mid:]
//			wg.Add(2)
//			go recursionScan(target, leftPart)
//			go recursionScan(target, rightPart)
//		}
//	}
//	wg.Add(1)
//	recursionScan(target, models.Config.Parameters)
//	wg.Wait()
//}

// Scan
// 要不要检查fatget呢？？？？
func (p *PCPTechniques) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache || target.Cache.CKIsAnyGet {
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
	paramsNoGetCacheKeys := make([]string, 0)
	if target.Cache.CKIsGet {
		if len(target.Cache.GetCacheKeys) == 0 {
			return
		}
		for _, param := range models.Config.Parameters {
			if !slices.Contains(target.Cache.GetCacheKeys, param) {
				paramsNoGetCacheKeys = append(paramsNoGetCacheKeys, param)
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go p.findVulnerability(target, paramsNoGetCacheKeys, &wg)
	wg.Wait()

	// 收集完所有漏洞参数后，统一报告
	p.reportCollectedVulnerabilities(target)
}

func (p *PCPTechniques) findVulnerabilityByAnyGet(target *models.TargetStruct) (bool, error) {
	pvMap := map[string]string{utils.RandomString(5): utils.RandomString(5)}
	var resp *http.Response
	var err error
	for range 3 {
		resp, err = GetResp(target, GET, pvMap)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false, err
	}
	if resp == nil {
		return false, nil
	}
	defer utils.CloseReader(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	for k, v := range pvMap {
		if RespContains2(string(respBody), v, resp.Header) {
			// 输出详细报告
			p.reportAnyGetVulnerability(target, k, v, resp, respBody)
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
	var resp *http.Response
	var err error
	for range 3 {
		resp, err = GetResp(target, GET, pvMap)
		if err == nil {
			break
		}
	}
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	if resp == nil {
		return
	}
	defer utils.CloseReader(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}

	// 状态码不同就可能是投毒（包括301/429等）
	if resp.StatusCode != target.Response.StatusCode {
		mid := len(params) / 2
		leftPart := params[:mid]
		rightPart := params[mid:]
		if len(params) == 1 {
			tmpReq, err := utils.CloneRequest(resp.Request)
			if err != nil {
				return
			}
			tmpResp, err := utils.CommonClient.Do(tmpReq)
			if err != nil {
				return
			}
			defer utils.CloseReader(tmpResp.Body)

			if tmpResp.StatusCode != target.Response.StatusCode {
				if utils.IsCacheHit(target, &tmpResp.Header) {
					for range 3 {
						shouldIsMissResp, err := GetResp(target, GET, pvMap)
						if err != nil {
							continue
						}
						isMiss := utils.IsCacheMiss(target, &shouldIsMissResp.Header)
						statusDiff := target.Response.StatusCode != shouldIsMissResp.StatusCode
						utils.CloseReader(shouldIsMissResp.Body)
						if isMiss && statusDiff {
							// Map 读写锁
							p.RWLock.Lock()
							p.PcpParams[target.Request.URL.String()] = append(p.PcpParams[target.Request.URL.String()], maps.Keys(pvMap)...)
							p.RWLock.Unlock()
							// 输出详细报告
							p.reportVulnerability(target, pvMap, shouldIsMissResp, nil, "status_change_miss")
							return
						}
					}
				}
				if utils.IsCacheMiss(target, &tmpResp.Header) {
					for range 3 {
						shouldIsHitReq, err := utils.CloneRequest(tmpResp.Request)
						if err != nil {
							continue
						}
						shouldIsHitResp, err := utils.CommonClient.Do(shouldIsHitReq)
						if err != nil {
							continue
						}
						isHit := utils.IsCacheHit(target, &shouldIsHitResp.Header)
						statusDiff := target.Response.StatusCode != shouldIsHitResp.StatusCode
						utils.CloseReader(shouldIsHitResp.Body)
						if isHit && statusDiff {
							// Map 读写锁
							p.RWLock.Lock()
							p.PcpParams[target.Request.URL.String()] = append(p.PcpParams[target.Request.URL.String()], maps.Keys(pvMap)...)
							p.RWLock.Unlock()
							// 输出详细报告
							p.reportVulnerability(target, pvMap, shouldIsHitResp, nil, "status_change_hit")
							return
						}
					}
				}
			}
			return
		}
		wg.Add(2)
		go p.findVulnerability(target, leftPart, wg)
		go p.findVulnerability(target, rightPart, wg)
	}

	if resp.StatusCode == target.Response.StatusCode {
		// 判断Body中是否存在某些字符串
		for param, value := range pvMap {
			if strings.Contains(string(respBody), "<"+value) {
				// 输出详细报告
				vulnMap := map[string]string{param: value}
				p.reportVulnerability(target, vulnMap, resp, respBody, "body_reflection")
				break
			}
		}

		for param, value := range pvMap {
			if resp.Header.Get(value) != "" {
				// 输出详细报告
				vulnMap := map[string]string{param: value}
				p.reportVulnerability(target, vulnMap, resp, respBody, "header_reflection")
				break
			}
		}
		return
	}
}

// reportAnyGetVulnerability 输出AnyGet漏洞的详细报告
func (p *PCPTechniques) reportAnyGetVulnerability(target *models.TargetStruct, param, value string,
	resp *http.Response, respBody []byte) {

	// 构建请求（已被注释，不再使用旧的立即报告逻辑）
	testReq, err := GetSourceRequestWithCacheKey(target)
	if err != nil || testReq == nil {
		// Fallback: 使用原始请求
		testReq, _ = utils.CloneRequest(target.Request)
	}
	if testReq != nil {
		q := testReq.URL.Query()
		q.Add(param, value)
		testReq.URL.RawQuery = q.Encode()
	}

	// 提取缓存键
	cacheKeys := []string{}
	if target.Cache.CKIsGet {
		cacheKeys = append(cacheKeys, target.Cache.GetCacheKeys...)
	}

	// 格式化请求和响应
	reqStr := output.FormatRequest(testReq, []string{param})
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, value)

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityHigh,
		Type:         output.VulnTypeParameterCP,
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: fmt.Sprintf("Any GET parameter (%s) is reflected in response", param),
		Request:      reqStr,
		Response:     respStr,
		Impact:       "Arbitrary GET parameters are cached and reflected - potential for XSS and cache poisoning attacks",
		Persistent:   true,
		Remediation: []string{
			"Implement strict parameter whitelisting",
			"Add all GET parameters to cache key",
			"Sanitize and validate all query parameters",
			"Consider implementing parameter filtering at CDN level",
		},
	}

	report.Print()
}

// reportVulnerability 收集漏洞参数（不立即报告）
func (p *PCPTechniques) reportVulnerability(target *models.TargetStruct, pvMap map[string]string,
	resp *http.Response, respBody []byte, vulnType string) {

	// 收集漏洞参数到map中
	targetURL := target.Request.URL.String()
	p.VulnParamsMutex.Lock()
	defer p.VulnParamsMutex.Unlock()

	for param := range pvMap {
		p.VulnParams[targetURL] = append(p.VulnParams[targetURL], VulnParam{
			Param:      param,
			StatusCode: resp.StatusCode,
			VulnType:   vulnType,
		})
	}

	// 不再立即报告，等收集完所有参数后统一报告
	return

	// 下面的代码暂时注释，保留原始报告逻辑作为模板

	// 构建请求
	testReq, err := GetSourceRequestWithCacheKey(target)
	if err != nil || testReq == nil {
		// Fallback: 使用原始请求
		testReq, _ = utils.CloneRequest(target.Request)
	}
	if testReq != nil {
		q := testReq.URL.Query()
		for k, v := range pvMap {
			q.Add(k, v)
		}
		testReq.URL.RawQuery = q.Encode()
	}

	// 提取缓存键
	cacheKeys := []string{}
	if target.Cache.CKIsGet {
		cacheKeys = append(cacheKeys, target.Cache.GetCacheKeys...)
	}

	// 确定攻击向量和影响
	var attackVector string
	var impact string
	var reflectedContent string
	var severity string

	switch vulnType {
	case "status_change_miss", "status_change_hit":
		attackVector = fmt.Sprintf("Parameter %v causes abnormal status code %d", maps.Keys(pvMap), resp.StatusCode)
		impact = "All users will receive error response when accessing this cached URL"
		severity = output.SeverityCritical
	case "body_reflection":
		attackVector = fmt.Sprintf("Parameter %v reflected in response body", maps.Keys(pvMap))
		impact = "Potential XSS attack - malicious payload can be cached and served to all users"
		severity = output.SeverityHigh
		for _, v := range pvMap {
			reflectedContent = v
			break
		}
	case "header_reflection":
		attackVector = fmt.Sprintf("Parameter %v reflected in response headers", maps.Keys(pvMap))
		impact = "Potential header injection - can manipulate cached response headers"
		severity = output.SeverityMedium
		for _, v := range pvMap {
			reflectedContent = v
			break
		}
	}

	// 格式化请求和响应
	reqStr := output.FormatRequest(testReq, maps.Keys(pvMap))
	bodySnippet := ""
	if respBody != nil {
		bodySnippet = output.ExtractBodySnippet(respBody, 300)
	}
	respStr := output.FormatResponse(resp, bodySnippet, reflectedContent)

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     severity,
		Type:         output.VulnTypeParameterCP,
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: attackVector,
		Request:      reqStr,
		Response:     respStr,
		Impact:       impact,
		Persistent:   true,
		Remediation: []string{
			fmt.Sprintf("Add parameter %v to the cache key configuration", maps.Keys(pvMap)),
			"Validate and sanitize all GET parameters",
			"Implement parameter whitelisting",
			"Consider removing unkeyed parameters from cache",
		},
	}

	report.Print()
}
