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

// WCD (Web Cache Deception) 检测技术
type WCD struct {
	// 常见的静态资源扩展名
	StaticExtensions []string
	// 常见的路径分隔符
	PathDelimiters []string
}

var WCDTechniques *WCD

func init() {
	WCDTechniques = NewWCD()
}

func NewWCD() *WCD {
	return &WCD{
		StaticExtensions: []string{
			".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
			".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
			".zip", ".tar", ".gz", ".xml", ".json", ".txt", ".html",
		},
		PathDelimiters: []string{
			"/", "%2f", "%5c", "\\", ";", "%3b",
		},
	}
}

// Scan 执行Web Cache Deception扫描
func (w *WCD) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}

	// 只对包含敏感信息的路径进行检测
	if !w.isSensitivePath(target.Request.URL.Path) {
		gologger.Debug().Msgf("WCD: Skipping non-sensitive path: %s", target.Request.URL.Path)
		return
	}

	gologger.Debug().Msgf("WCD: Testing sensitive path: %s", target.Request.URL.Path)

	// 获取原始响应作为基准
	baseResp := target.Response
	baseBody := target.RespBody

	// 测试各种扩展名组合
	for _, ext := range w.StaticExtensions {
		for _, delimiter := range w.PathDelimiters {
			// 构造测试URL
			testPath := w.constructTestPath(target.Request.URL.Path, delimiter, ext)
			
			// 发送测试请求
			vulnerable, resp, respBody := w.testPath(target, testPath, baseResp, baseBody)
			
			if vulnerable {
				w.reportVulnerability(target, testPath, ext, delimiter, resp, respBody)
				return // 找到一个漏洞就够了
			}
		}
	}
}

// isSensitivePath 判断是否为敏感路径
func (w *WCD) isSensitivePath(path string) bool {
	sensitiveKeywords := []string{
		"profile", "account", "user", "admin", "dashboard", "settings",
		"api", "data", "private", "personal", "member", "my",
	}

	pathLower := strings.ToLower(path)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(pathLower, keyword) {
			return true
		}
	}

	return false
}

// constructTestPath 构造测试路径
func (w *WCD) constructTestPath(basePath, delimiter, extension string) string {
	// 移除尾部斜杠
	basePath = strings.TrimSuffix(basePath, "/")
	
	// 根据delimiter构造路径
	if delimiter == "/" {
		return basePath + "/nonexistent" + extension
	}
	
	// 对于编码的分隔符，直接拼接
	return basePath + delimiter + "nonexistent" + extension
}

// testPath 测试特定路径是否存在WCD漏洞
func (w *WCD) testPath(target *models.TargetStruct, testPath string, baseResp *http.Response, baseBody []byte) (bool, *http.Response, []byte) {
	// 克隆请求
	testReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		gologger.Debug().Msgf("WCD: Failed to clone request: %v", err)
		return false, nil, nil
	}

	// 修改路径
	testReq.URL.Path = testPath
	testReq.RequestURI = testPath

	// 发送请求（带重试）
	var resp *http.Response
	for i := 0; i < 3; i++ {
		resp, err = utils.CommonClient.Do(testReq)
		if err == nil {
			break
		}
		gologger.Debug().Msgf("WCD: Request failed (attempt %d/3): %v", i+1, err)
	}

	if err != nil || resp == nil {
		return false, nil, nil
	}

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	utils.CloseReader(resp.Body)
	if err != nil {
		return false, nil, nil
	}

	// 检查是否存在漏洞
	return w.checkVulnerability(baseResp, baseBody, resp, respBody), resp, respBody
}

// checkVulnerability 检查是否存在WCD漏洞
func (w *WCD) checkVulnerability(baseResp *http.Response, baseBody []byte, testResp *http.Response, testBody []byte) bool {
	// 1. 检查状态码（应该相同或都是200系列）
	if testResp.StatusCode >= 400 {
		// 如果返回错误状态码，说明路径不存在，不是WCD
		return false
	}

	// 2. 检查是否被缓存 (传nil因为这里不需要检查target的Indicators)
	if !utils.IsCacheHit(nil, &testResp.Header) {
		// 如果没有被缓存，不是WCD漏洞
		return false
	}

	// 3. 检查内容相似度
	similarity := w.calculateSimilarity(baseBody, testBody)
	if similarity < 0.7 { // 相似度阈值70%
		return false
	}

	// 4. 检查响应中是否包含敏感信息标识
	if w.containsSensitiveInfo(testBody) {
		return true
	}

	// 5. 如果响应完全相同且被缓存，也认为存在漏洞
	if similarity > 0.95 {
		return true
	}

	return false
}

// calculateSimilarity 计算两个响应体的相似度
func (w *WCD) calculateSimilarity(body1, body2 []byte) float64 {
	if len(body1) == 0 || len(body2) == 0 {
		return 0
	}

	// 简单的相似度计算：比较长度和部分内容
	lenDiff := float64(abs(len(body1) - len(body2)))
	maxLen := float64(max(len(body1), len(body2)))
	
	// 长度相似度
	lengthSimilarity := 1.0 - (lenDiff / maxLen)

	// 内容相似度（简化版：比较前1000字节）
	compareLen := min(len(body1), len(body2), 1000)
	matchCount := 0
	for i := 0; i < compareLen; i++ {
		if body1[i] == body2[i] {
			matchCount++
		}
	}
	contentSimilarity := float64(matchCount) / float64(compareLen)

	// 综合相似度
	return (lengthSimilarity + contentSimilarity) / 2.0
}

// containsSensitiveInfo 检查响应是否包含敏感信息
func (w *WCD) containsSensitiveInfo(body []byte) bool {
	bodyStr := strings.ToLower(string(body))
	
	sensitivePatterns := []string{
		"email", "password", "token", "session", "csrf",
		"api_key", "secret", "private", "balance", "credit",
		"ssn", "social security", "phone", "address",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(bodyStr, pattern) {
			return true
		}
	}

	return false
}

// reportVulnerability 报告WCD漏洞
func (w *WCD) reportVulnerability(target *models.TargetStruct, testPath, extension, delimiter string, resp *http.Response, respBody []byte) {
	// 构建攻击请求
	testReq, _ := utils.CloneRequest(target.Request)
	if testReq != nil {
		testReq.URL.Path = testPath
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
	payloadInfo := fmt.Sprintf("Path with static extension: %s (delimiter: %s)", extension, delimiter)
	reqStr := output.FormatRequestSimple(testReq, payloadInfo)
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, "")

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityCritical,
		Type:         "Web Cache Deception (WCD)",
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: fmt.Sprintf("Path with static extension %s causes sensitive page to be cached", extension),
		Request:      reqStr,
		Response:     respStr,
		Impact:       "Sensitive user information is cached and accessible to attackers - affects ALL users visiting the same URL",
		Persistent:   true,
		Remediation: []string{
			"Do not cache responses based solely on file extension",
			"Implement proper cache control headers for dynamic content",
			"Validate the actual content type before caching",
			"Use Cache-Control: private for sensitive pages",
			fmt.Sprintf("Example vulnerable URL: %s%s", target.Request.URL.Path, extension),
		},
	}

	// 输出报告
	report.Print()
}

// 辅助函数
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b, c int) int {
	result := a
	if b < result {
		result = b
	}
	if c < result {
		result = c
	}
	return result
}

