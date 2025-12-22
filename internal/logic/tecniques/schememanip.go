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

// SchemeManipulation (Scheme Manipulation) 检测技术
// 跨协议缓存投毒：HTTP <-> HTTPS
type SchemeManipulation struct{}

var SchemeManipTechniques *SchemeManipulation

func init() {
	SchemeManipTechniques = NewSchemeManipulation()
}

func NewSchemeManipulation() *SchemeManipulation {
	return &SchemeManipulation{}
}

// Scan 执行Scheme Manipulation扫描
func (s *SchemeManipulation) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}

	// 只对HTTPS站点进行测试（测试HTTP->HTTPS投毒）
	if target.Request.URL.Scheme != "https" {
		gologger.Debug().Msgf("SchemeManip: Skipping non-HTTPS target: %s", target.Request.URL)
		return
	}

	gologger.Debug().Msgf("SchemeManip: Testing %s", target.Request.URL)

	// 测试HTTP->HTTPS投毒
	s.testHTTPtoHTTPS(target)
}

// testHTTPtoHTTPS 测试从HTTP向HTTPS的缓存投毒
func (s *SchemeManipulation) testHTTPtoHTTPS(target *models.TargetStruct) {
	// 1. 构造HTTP版本的URL（带payload）
	httpURL := strings.Replace(target.Request.URL.String(), "https://", "http://", 1)
	
	// 2. 通过HTTP注入恶意payload
	payload := "evil-" + utils.RandomString(8)
	poisoned := s.poisonViaHTTP(httpURL, payload, target)
	if !poisoned {
		gologger.Debug().Msgf("SchemeManip: Failed to poison via HTTP")
		return
	}

	// 3. 通过HTTPS检查是否获取到被投毒的缓存
	if s.checkHTTPSPoisoned(target, payload) {
		s.reportVulnerability(target, httpURL, payload)
	}
}

// poisonViaHTTP 通过HTTP注入payload
func (s *SchemeManipulation) poisonViaHTTP(httpURL, payload string, target *models.TargetStruct) bool {
	// 构造HTTP请求
	req, err := http.NewRequest("GET", httpURL, nil)
	if err != nil {
		gologger.Debug().Msgf("SchemeManip: Failed to create HTTP request: %v", err)
		return false
	}

	// 复制原始请求的headers
	for k, v := range target.Request.Header {
		req.Header[k] = v
	}

	// 添加payload到header（使用X-Forwarded-Host或其他未键入的header）
	req.Header.Set("X-Forwarded-Host", payload)
	req.Header.Set("X-Original-URL", "/"+payload)

	// 发送请求
	var resp *http.Response
	for i := 0; i < 3; i++ {
		resp, err = utils.CommonClient.Do(req)
		if err == nil && resp != nil {
			break
		}
	}

	if err != nil || resp == nil {
		return false
	}

	body, _ := io.ReadAll(resp.Body)
	utils.CloseReader(resp.Body)

	// 检查是否成功注入且被缓存
	return strings.Contains(string(body), payload) && utils.IsCacheHit(target, &resp.Header)
}

// checkHTTPSPoisoned 检查HTTPS是否获取到被投毒的缓存
func (s *SchemeManipulation) checkHTTPSPoisoned(target *models.TargetStruct, payload string) bool {
	// 发送3次验证请求
	poisonedCount := 0
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

		// 检查是否包含payload且来自缓存
		if strings.Contains(string(body), payload) && utils.IsCacheHit(target, &resp.Header) {
			poisonedCount++
		}
	}

	// 至少2次验证成功
	return poisonedCount >= 2
}

// reportVulnerability 报告Scheme Manipulation漏洞
func (s *SchemeManipulation) reportVulnerability(target *models.TargetStruct, httpURL, payload string) {
	// 构建攻击请求（HTTP版本）
	req, _ := http.NewRequest("GET", httpURL, nil)
	if req != nil {
		req.Header.Set("X-Forwarded-Host", payload)
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
	payloadInfo := fmt.Sprintf("Cross-scheme poisoning: HTTP -> HTTPS, payload: %s", payload)
	reqStr := output.FormatRequestSimple(req, payloadInfo)
	respStr := fmt.Sprintf("HTTPS request returns poisoned HTTP cache\nPayload: %s [REFLECTED]", payload)

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityMedium,
		Type:         "Scheme Manipulation Cache Poisoning",
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: fmt.Sprintf("Cross-protocol cache poisoning: HTTP (%s) poisons HTTPS cache", httpURL),
		Request:      reqStr,
		Response:     respStr,
		Impact:       "HTTP injected content served over HTTPS - potential mixed content attacks and security bypass",
		Persistent:   true,
		Remediation: []string{
			"Include URL scheme (http/https) in cache key",
			"Separate HTTP and HTTPS caches completely",
			"Redirect all HTTP traffic to HTTPS at CDN level",
			"Implement HSTS (HTTP Strict Transport Security)",
		},
	}

	// 输出报告
	report.Print()
}

