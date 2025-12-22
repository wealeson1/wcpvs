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

// CacheKeyNormalization 缓存键规范化攻击检测
// 利用前端代理和后端服务器对URL规范化处理的差异
type CacheKeyNormalization struct {
	// URL编码测试用例
	EncodingVariants []URLVariant
	// 参数顺序测试用例
	ParamOrderVariants []ParamOrderTest
	// 大小写测试用例
	CaseVariants []CaseTest
}

type URLVariant struct {
	Name     string
	Variant1 string // 第一种形式
	Variant2 string // 第二种形式（规范化后应该相同）
}

type ParamOrderTest struct {
	Order1 string
	Order2 string
}

type CaseTest struct {
	Lower string
	Upper string
	Mixed string
}

var NormalizationTechniques *CacheKeyNormalization

func init() {
	NormalizationTechniques = NewCacheKeyNormalization()
}

func NewCacheKeyNormalization() *CacheKeyNormalization {
	return &CacheKeyNormalization{
		EncodingVariants: []URLVariant{
			{Name: "Dot encoding", Variant1: "/..", Variant2: "/%2e%2e"},
			{Name: "Slash encoding", Variant1: "/path/", Variant2: "/path%2f"},
			{Name: "Null byte", Variant1: "/path", Variant2: "/path%00"},
			{Name: "Double encoding", Variant1: "/path", Variant2: "/path%252e"},
			{Name: "Unicode", Variant1: "/path", Variant2: "/%u002e%u002e"},
			{Name: "Mixed encoding", Variant1: "/../admin", Variant2: "/%2e%2e%2fadmin"},
		},
		ParamOrderVariants: []ParamOrderTest{
			{Order1: "a=1&b=2", Order2: "b=2&a=1"},
			{Order1: "callback=test&id=123", Order2: "id=123&callback=test"},
		},
		CaseVariants: []CaseTest{
			{Lower: "/api/user", Upper: "/API/USER", Mixed: "/Api/User"},
			{Lower: "/admin", Upper: "/ADMIN", Mixed: "/Admin"},
		},
	}
}

// Scan 执行缓存键规范化攻击扫描
func (c *CacheKeyNormalization) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}

	gologger.Debug().Msgf("Normalization: Starting scan for %s", target.Request.URL)

	// 1. 测试URL编码变体
	if c.testEncodingVariants(target) {
		return
	}

	// 2. 测试参数顺序
	if c.testParameterOrder(target) {
		return
	}

	// 3. 测试大小写
	if c.testCaseVariants(target) {
		return
	}
}

// testEncodingVariants 测试URL编码变体
func (c *CacheKeyNormalization) testEncodingVariants(target *models.TargetStruct) bool {
	basePath := target.Request.URL.Path

	for _, variant := range c.EncodingVariants {
		// 构造两个变体URL
		path1 := basePath + variant.Variant1
		path2 := basePath + variant.Variant2

		// 测试是否存在规范化差异
		if c.testNormalizationDiff(target, path1, path2, variant.Name) {
			return true
		}
	}

	return false
}

// testParameterOrder 测试参数顺序
func (c *CacheKeyNormalization) testParameterOrder(target *models.TargetStruct) bool {
	// 只对有查询参数的URL进行测试
	if target.Request.URL.RawQuery == "" {
		return false
	}

	// 生成恶意payload
	payload := "evil-" + utils.RandomString(8)

	for _, test := range c.ParamOrderVariants {
		// 构造两个不同参数顺序的URL
		query1 := test.Order1 + "&x-evil=" + payload
		query2 := test.Order2 + "&x-evil=" + payload

		// 测试1: 使用order1注入
		resp1, body1 := c.sendRequestWithQuery(target, query1)
		if resp1 == nil || !strings.Contains(string(body1), payload) {
			continue
		}

		// 测试2: 使用order2检查是否获取到缓存
		resp2, body2 := c.sendRequestWithQuery(target, query2)
		if resp2 == nil {
			continue
		}

		// 如果order2也返回payload，说明缓存忽略了参数顺序
		if strings.Contains(string(body2), payload) && utils.IsCacheHit(target, &resp2.Header) {
			c.reportVulnerability(target, "Parameter Order", query1, query2, resp2, body2)
			return true
		}
	}

	return false
}

// testCaseVariants 测试大小写变体
func (c *CacheKeyNormalization) testCaseVariants(target *models.TargetStruct) bool {
	payload := "evil-" + utils.RandomString(8)

	for _, test := range c.CaseVariants {
		// 使用小写路径注入payload
		lowerPath := test.Lower
		resp1, body1 := c.sendRequestWithPath(target, lowerPath, payload)
		if resp1 == nil || !strings.Contains(string(body1), payload) {
			continue
		}

		// 使用大写路径检查缓存
		upperPath := test.Upper
		resp2, body2 := c.sendRequestWithPath(target, upperPath, "")
		if resp2 == nil {
			continue
		}

		// 如果大写路径返回小写路径注入的payload
		if strings.Contains(string(body2), payload) && utils.IsCacheHit(target, &resp2.Header) {
			c.reportVulnerability(target, "Case Sensitivity", lowerPath, upperPath, resp2, body2)
			return true
		}

		// 测试混合大小写
		mixedPath := test.Mixed
		resp3, body3 := c.sendRequestWithPath(target, mixedPath, "")
		if resp3 != nil && strings.Contains(string(body3), payload) && utils.IsCacheHit(target, &resp3.Header) {
			c.reportVulnerability(target, "Case Sensitivity", lowerPath, mixedPath, resp3, body3)
			return true
		}
	}

	return false
}

// testNormalizationDiff 测试规范化差异
func (c *CacheKeyNormalization) testNormalizationDiff(target *models.TargetStruct, path1, path2, variantName string) bool {
	payload := "evil-" + utils.RandomString(8)

	// 1. 使用variant1注入payload
	resp1, body1 := c.sendRequestWithPath(target, path1, payload)
	if resp1 == nil {
		return false
	}

	// 2. 检查是否包含payload且被缓存
	if !strings.Contains(string(body1), payload) || !utils.IsCacheHit(target, &resp1.Header) {
		return false
	}

	// 3. 使用variant2检查是否获取到相同的缓存
	resp2, body2 := c.sendRequestWithPath(target, path2, "")
	if resp2 == nil {
		return false
	}

	// 4. 如果variant2也返回payload，说明存在规范化问题
	if strings.Contains(string(body2), payload) && utils.IsCacheHit(target, &resp2.Header) {
		c.reportVulnerability(target, variantName, path1, path2, resp2, body2)
		return true
	}

	return false
}

// sendRequestWithQuery 发送带指定查询字符串的请求
func (c *CacheKeyNormalization) sendRequestWithQuery(target *models.TargetStruct, query string) (*http.Response, []byte) {
	req, err := utils.CloneRequest(target.Request)
	if err != nil {
		return nil, nil
	}

	req.URL.RawQuery = query

	var resp *http.Response
	for i := 0; i < 3; i++ {
		resp, err = utils.CommonClient.Do(req)
		if err == nil && resp != nil {
			break
		}
	}

	if err != nil || resp == nil {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	utils.CloseReader(resp.Body)
	if err != nil {
		return nil, nil
	}

	return resp, body
}

// sendRequestWithPath 发送带指定路径的请求
func (c *CacheKeyNormalization) sendRequestWithPath(target *models.TargetStruct, path, payload string) (*http.Response, []byte) {
	req, err := utils.CloneRequest(target.Request)
	if err != nil {
		return nil, nil
	}

	req.URL.Path = path
	if payload != "" {
		// 通过header注入payload
		req.Header.Set("X-Forwarded-Host", payload)
	}

	var resp *http.Response
	for i := 0; i < 3; i++ {
		resp, err = utils.CommonClient.Do(req)
		if err == nil && resp != nil {
			break
		}
	}

	if err != nil || resp == nil {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	utils.CloseReader(resp.Body)
	if err != nil {
		return nil, nil
	}

	return resp, body
}

// reportVulnerability 报告规范化攻击漏洞
func (c *CacheKeyNormalization) reportVulnerability(target *models.TargetStruct, variantType, variant1, variant2 string, resp *http.Response, respBody []byte) {
	// 构建攻击请求
	testReq, _ := utils.CloneRequest(target.Request)
	if testReq != nil {
		if strings.Contains(variant1, "=") {
			// 查询参数变体
			testReq.URL.RawQuery = variant1
		} else {
			// 路径变体
			testReq.URL.Path = variant1
		}
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
	payloadInfo := fmt.Sprintf("Normalization attack: %s\nVariant 1: %s\nVariant 2: %s", variantType, variant1, variant2)
	reqStr := output.FormatRequestSimple(testReq, payloadInfo)
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, "")

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityHigh,
		Type:         "Cache Key Normalization Attack",
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: fmt.Sprintf("%s: Different URL variants (%s vs %s) map to same cache entry", variantType, variant1, variant2),
		Request:      reqStr,
		Response:     respStr,
		Impact:       "Attacker can poison cache using one URL variant while victims access via another - bypasses cache key restrictions",
		Persistent:   true,
		Remediation: []string{
			"Normalize URLs consistently before caching",
			"Include full normalized URL in cache key",
			"Reject ambiguous URL encodings at CDN level",
			fmt.Sprintf("Both '%s' and '%s' should generate different cache keys", variant1, variant2),
		},
	}

	// 输出报告
	report.Print()
}

