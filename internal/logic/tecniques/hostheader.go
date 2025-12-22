package tecniques

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

// HostHeaderCP (Host Header Cache Poisoning) 检测技术
type HostHeaderCP struct {
	// 测试用的恶意Host值
	EvilHosts []string
}

var HostHeaderCPTechniques *HostHeaderCP

func init() {
	HostHeaderCPTechniques = NewHostHeaderCP()
}

func NewHostHeaderCP() *HostHeaderCP {
	return &HostHeaderCP{
		EvilHosts: []string{
			"evil-" + utils.RandomString(8) + ".com",
			"attacker-" + utils.RandomString(6) + ".net",
		},
	}
}

// Scan 执行Host Header缓存投毒扫描
func (h *HostHeaderCP) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}

	gologger.Debug().Msgf("HostHeader: Starting scan for %s", target.Request.URL)

	// 测试每个恶意Host
	for _, evilHost := range h.EvilHosts {
		if h.testHostHeader(target, evilHost) {
			return // 找到一个漏洞就返回
		}
	}
}

// testHostHeader 测试特定的Host header
func (h *HostHeaderCP) testHostHeader(target *models.TargetStruct, evilHost string) bool {
	// 1. 使用恶意Host发送请求
	poisonResp, poisonBody := h.sendPoisonRequest(target, evilHost)
	if poisonResp == nil {
		return false
	}

	// 2. 检查响应是否被缓存
	if !utils.IsCacheHit(target, &poisonResp.Header) {
		gologger.Debug().Msgf("HostHeader: Response not cached for evil host: %s", evilHost)
		return false
	}

	// 3. 检查响应中是否包含恶意Host
	if !h.checkReflection(poisonBody, evilHost) {
		gologger.Debug().Msgf("HostHeader: Evil host not reflected: %s", evilHost)
		return false
	}

	// 4. 验证漏洞持久性：使用正常Host再次请求
	if !h.verifyPersistence(target, evilHost) {
		gologger.Debug().Msgf("HostHeader: Poisoning not persistent for: %s", evilHost)
		return false
	}

	// 5. 确认漏洞，生成报告
	h.reportVulnerability(target, evilHost, poisonResp, poisonBody)
	return true
}

// sendPoisonRequest 发送带有恶意Host的请求
func (h *HostHeaderCP) sendPoisonRequest(target *models.TargetStruct, evilHost string) (*http.Response, []byte) {
	// 克隆请求
	req, err := utils.CloneRequest(target.Request)
	if err != nil {
		gologger.Debug().Msgf("HostHeader: Failed to clone request: %v", err)
		return nil, nil
	}

	// 修改Host header
	req.Host = evilHost
	req.Header.Set("Host", evilHost)

	// 发送请求（带重试）
	var resp *http.Response
	for i := 0; i < 3; i++ {
		resp, err = utils.CommonClient.Do(req)
		if err == nil && resp != nil {
			break
		}
		gologger.Debug().Msgf("HostHeader: Request failed (attempt %d/3): %v", i+1, err)
	}

	if err != nil || resp == nil {
		return nil, nil
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	utils.CloseReader(resp.Body)
	if err != nil {
		return nil, nil
	}

	return resp, body
}

// checkReflection 检查响应中是否反射了恶意Host
func (h *HostHeaderCP) checkReflection(body []byte, evilHost string) bool {
	bodyStr := string(body)

	// 1. 检查HTML中的链接
	if strings.Contains(bodyStr, "http://"+evilHost) ||
		strings.Contains(bodyStr, "https://"+evilHost) ||
		strings.Contains(bodyStr, "//"+evilHost) {
		return true
	}

	// 2. 检查常见的反射位置
	reflectionPatterns := []string{
		fmt.Sprintf(`href="%s`, evilHost),
		fmt.Sprintf(`src="%s`, evilHost),
		fmt.Sprintf(`href='%s`, evilHost),
		fmt.Sprintf(`src='%s`, evilHost),
		fmt.Sprintf(`url(%s`, evilHost),
		fmt.Sprintf(`"host":"%s"`, evilHost),
		fmt.Sprintf(`'host':'%s'`, evilHost),
	}

	for _, pattern := range reflectionPatterns {
		if strings.Contains(bodyStr, pattern) {
			return true
		}
	}

	return false
}

// verifyPersistence 验证投毒是否持久化
func (h *HostHeaderCP) verifyPersistence(target *models.TargetStruct, evilHost string) bool {
	// 发送3次验证请求
	persistCount := 0
	for i := 0; i < 3; i++ {
		// 每次循环都克隆新请求，避免Body被复用
		verifyReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			continue
		}

		resp, err := utils.CommonClient.Do(verifyReq)
		if err != nil || resp == nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		utils.CloseReader(resp.Body)
		if err != nil {
			continue
		}

		// 检查是否仍然包含恶意Host
		if h.checkReflection(body, evilHost) && utils.IsCacheHit(target, &resp.Header) {
			persistCount++
		}
	}

	// 至少2次验证成功才认为是持久的
	return persistCount >= 2
}

// reportVulnerability 报告Host Header投毒漏洞
func (h *HostHeaderCP) reportVulnerability(target *models.TargetStruct, evilHost string, resp *http.Response, respBody []byte) {
	// 构建攻击请求
	testReq, _ := utils.CloneRequest(target.Request)
	if testReq != nil {
		testReq.Host = evilHost
		testReq.Header.Set("Host", evilHost)
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
	payloadInfo := fmt.Sprintf("Malicious Host header: %s", evilHost)
	reqStr := output.FormatRequestSimple(testReq, payloadInfo)
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, evilHost)

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityHigh,
		Type:         "Host Header Cache Poisoning",
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: fmt.Sprintf("Host header injection (%s) is reflected in response and cached", evilHost),
		Request:      reqStr,
		Response:     respStr,
		Impact:       "Attacker can inject malicious links/resources that will be served to all users - potential XSS and resource hijacking",
		Persistent:   true,
		Remediation: []string{
			"Add Host header to cache key configuration",
			"Validate Host header against whitelist before use",
			"Use absolute URLs instead of relying on Host header",
			"Implement strict Host header validation at CDN level",
		},
	}

	// 输出报告
	report.Print()
}

