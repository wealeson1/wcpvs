package tecniques

import (
	"fmt"
	"strings"

	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

// reportCollectedVulnerabilities 统一报告收集到的所有漏洞参数
func (p *PCPTechniques) reportCollectedVulnerabilities(target *models.TargetStruct) {
	p.VulnParamsMutex.Lock()
	defer p.VulnParamsMutex.Unlock()

	targetURL := target.Request.URL.String()
	vulnParams := p.VulnParams[targetURL]

	if len(vulnParams) == 0 {
		return // 没有漏洞
	}

	// 按状态码分组漏洞参数
	groupedByStatus := make(map[int][]string)
	for _, vp := range vulnParams {
		groupedByStatus[vp.StatusCode] = append(groupedByStatus[vp.StatusCode], vp.Param)
	}

	// 为每个状态码组生成一个报告
	for statusCode, params := range groupedByStatus {
		// 构建请求
		testReq, err := GetSourceRequestWithCacheKey(target)
		if err != nil || testReq == nil {
			testReq, _ = utils.CloneRequest(target.Request)
		}

		// 添加所有有问题的参数到请求中
		if testReq != nil {
			q := testReq.URL.Query()
			for _, param := range params {
				q.Add(param, utils.RandomString(7))
			}
			testReq.URL.RawQuery = q.Encode()
		}

		// 提取缓存键
		cacheKeys := []string{}
		if target.Cache.CKIsGet {
			cacheKeys = append(cacheKeys, target.Cache.GetCacheKeys...)
		}
		if target.Cache.CKIsHeader {
			cacheKeys = append(cacheKeys, target.Cache.HeaderCacheKeys...)
		}

		// 构建攻击向量描述
		paramList := strings.Join(params, ", ")
		attackVector := fmt.Sprintf("Parameters [%s] (not in cache keys) cause abnormal status code %d", paramList, statusCode)

		// 格式化请求
		reqStr := output.FormatRequest(testReq, params)

		// 构建响应描述
		respStr := fmt.Sprintf("HTTP/1.1 %d\n(Response cached by CDN)\n\nNote: %d vulnerable parameters found", statusCode, len(params))

		// 创建漏洞报告
		report := &output.VulnerabilityReport{
			Severity:     output.SeverityCritical,
			Type:         output.VulnTypeParameterCP,
			Target:       targetURL,
			CDN:          utils.DetectCDNType(target.Response),
			CacheKeys:    cacheKeys,
			AttackVector: attackVector,
			Request:      reqStr,
			Response:     respStr,
			Impact:       fmt.Sprintf("Cache Poisoning DoS: All users will receive %d error when accessing this URL. %d unkeyed parameters can be exploited.", statusCode, len(params)),
			Persistent:   true,
			Remediation: []string{
				fmt.Sprintf("Add parameters [%s] to the cache key configuration", paramList),
				"Validate and sanitize all GET parameters",
				"Implement parameter whitelisting",
				"Do not cache error responses (3xx, 4xx, 5xx)",
			},
		}

		report.Print()
	}

	// 清除已报告的漏洞
	delete(p.VulnParams, targetURL)
}

