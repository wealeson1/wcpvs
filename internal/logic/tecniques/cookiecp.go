package tecniques

import (
	"fmt"
	"io"
	"net/http"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
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
		respBody, err := io.ReadAll(resp.Body)
		utils.CloseReader(resp.Body)
		if err != nil {
			gologger.Error().Msg("CCPTechniques.Scan read body error: " + err.Error())
			continue
		}

		contains := RespContains(resp, "<"+randomValue)
		if contains {
			// 输出详细报告
			c.reportVulnerability(target, cookie.Name, randomValue, resp, respBody)
		}
	}
}

// reportVulnerability 输出Cookie CP漏洞的详细报告
func (c *CookieCP) reportVulnerability(target *models.TargetStruct, cookieName, cookieValue string,
	resp *http.Response, respBody []byte) {

	// 构建请求
	testReq, err := utils.CloneRequest(target.Request)
	if err != nil || testReq == nil {
		gologger.Debug().Msgf("Failed to clone request for CCP report: %v", err)
		testReq = target.Request // Fallback
	}
	if testReq != nil {
		testReq.Header.Del("Cookie")
		testReq.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}

	// 提取缓存键
	cacheKeys := []string{}
	if target.Cache.CKisCookie && len(target.Cache.CookieCacheKeys) > 0 {
		cacheKeys = append(cacheKeys, "Cookie: "+target.Cache.CookieCacheKeys[0])
	}

	// 格式化请求和响应
	reqStr := output.FormatRequest(testReq, []string{"Cookie"})
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, cookieValue)

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityHigh,
		Type:         output.VulnTypeCookieCP,
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: fmt.Sprintf("Cookie %s is reflected in response body", cookieName),
		Request:      reqStr,
		Response:     respStr,
		Impact:       "Cookie values can be cached and reflected to all users - potential for session hijacking and XSS",
		Persistent:   true,
		Remediation: []string{
			fmt.Sprintf("Add Cookie '%s' to the cache key configuration", cookieName),
			"Validate and sanitize all cookie values before reflection",
			"Consider not caching responses with user-specific data",
			"Implement proper session management",
		},
	}

	report.Print()
}
