package cpdos

import (
	"fmt"
	"net/http"

	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

// ReportCPDoSVulnerability 输出CPDoS漏洞的详细报告（通用函数）
func ReportCPDoSVulnerability(target *models.TargetStruct, vulnType, attackVector string, 
	resp *http.Response, respBody []byte, testReq *http.Request, payloadInfo string) {
	
	// 提取缓存键
	cacheKeys := []string{}
	if target.Cache.CKIsGet {
		cacheKeys = append(cacheKeys, target.Cache.GetCacheKeys...)
	}
	if target.Cache.CKIsHeader {
		cacheKeys = append(cacheKeys, target.Cache.HeaderCacheKeys...)
	}
	
	// 格式化请求和响应
	reqStr := output.FormatRequestSimple(testReq, payloadInfo)
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, "")
	
	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityCritical,
		Type:         vulnType,
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: attackVector,
		Request:      reqStr,
		Response:     respStr,
		Impact:       fmt.Sprintf("Service becomes unavailable for ALL users - cached error response (status %d)", resp.StatusCode),
		Persistent:   true,
		Remediation: []string{
			"Configure cache to not cache error responses (4xx, 5xx)",
			"Implement strict input validation before caching",
			"Set appropriate cache control headers for error responses",
			"Monitor and alert on cached error responses",
		},
	}
	
	report.Print()
}

