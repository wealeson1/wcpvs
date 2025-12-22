package tecniques

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"golang.org/x/exp/maps"
)

type HeaderCP struct {
	HcpParams map[string][]string
	RWLock    sync.RWMutex
}

var HCPTechniques *HeaderCP

func init() {
	HCPTechniques = NewHeaderCP()
}

func NewHeaderCP() *HeaderCP {
	return &HeaderCP{
		HcpParams: make(map[string][]string),
		RWLock:    sync.RWMutex{},
	}
}

func (h *HeaderCP) Scan2(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}
	// 使用WaitGroup来等待所有goroutines完成
	var wg sync.WaitGroup
	// 获取unkeyed headers
	unkeyedHeaders, err := GetUnkeyedHeaders(target)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	var recursionScan func(target *models.TargetStruct, unkeyedHeaders []string)
	recursionScan = func(target *models.TargetStruct, unkeyedHeaders []string) {
		defer wg.Done()
		if len(unkeyedHeaders) == 0 {
			return
		}
		mid := len(unkeyedHeaders) / 2
		// 防止出现意外，陷入死循环
		if mid < 1 {
			return
		}
		leftPart := unkeyedHeaders[:mid]
		rightPart := unkeyedHeaders[mid:]
		payloadMap := make(map[string]string)
		for _, header := range unkeyedHeaders {
			payloadMap[header] = utils.RandomString(5)
		}
		resp, err := GetResp(target, HEADER, payloadMap)
		if err != nil {
			if resp != nil {
				utils.CloseReader(resp.Body)
			}
			wg.Add(2)
			go recursionScan(target, leftPart)
			go recursionScan(target, rightPart)
			return
		}
		if resp.StatusCode == target.Response.StatusCode {
			respHeaders := resp.Header
			respBodyStr, err := io.ReadAll(resp.Body)
			utils.CloseReader(resp.Body)
			if err != nil {
				gologger.Error().Msg("CCPTechniques.Scan" + err.Error() + ":")
				return
			}
			for k, v := range payloadMap {
				if strings.Contains(string(respBodyStr), "<"+v) {
					// 这里是Scan2的简化检测，不输出详细报告
					gologger.Debug().Msgf("Potential HCP (Scan2) for %s - Header: %s", target.Request.URL, k)
				}
				if respHeaders.Get(v) != "" {
					gologger.Debug().Msgf("Potential HCP header reflection (Scan2) for %s - Header: %s", target.Request.URL, k)
				}
			}
			return
		}
		// 响应码异常，关闭后递归
		utils.CloseReader(resp.Body)
		wg.Add(2)
		go recursionScan(target, leftPart)
		go recursionScan(target, rightPart)
	}
	wg.Add(1)
	go recursionScan(target, unkeyedHeaders)
	wg.Wait()
}

// Scan
// 异常状态码检测,检查XSS和CRLF漏洞
func (h *HeaderCP) Scan(target *models.TargetStruct) {
	var wg sync.WaitGroup
	if target.Cache.NoCache {
		return
	}

	// 智能分批扫描：先检测服务器支持的最大header数量
	maxHeaders := h.detectMaxHeaders(target)
	if maxHeaders <= 0 {
		maxHeaders = 50 // 默认50个
	}

	// 预留安全余量（10个header）
	batchSize := maxHeaders - 10
	if batchSize < 10 {
		batchSize = 10
	}

	gologger.Debug().Msgf("Detected max headers: %d, using batch size: %d", maxHeaders, batchSize)

	// 分批扫描
	allHeaders := models.Config.Headers
	for i := 0; i < len(allHeaders); i += batchSize {
		end := i + batchSize
		if end > len(allHeaders) {
			end = len(allHeaders)
		}
		batch := allHeaders[i:end]

		wg.Add(1)
		go h.findVulnerability(target, batch, &wg)
	}

	wg.Wait()
	// 漏洞已在findVulnerability中详细输出，这里不再重复
}

// detectMaxHeaders 使用二分法检测服务器支持的最大header数量
func (h *HeaderCP) detectMaxHeaders(target *models.TargetStruct) int {
	left, right := 10, 200
	maxFound := 10

	for left <= right {
		mid := (left + right) / 2

		// 测试mid个headers
		testReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			return 50 // 默认值
		}

		// 添加mid个随机headers
		for i := 0; i < mid; i++ {
			testReq.Header.Add(utils.RandomString(5), utils.RandomString(5))
		}

		resp, err := utils.CommonClient.Do(testReq)
		if err != nil {
			// 网络错误，尝试更小的值
			right = mid - 1
			continue
		}
		utils.CloseReader(resp.Body)

		// 检查状态码
		if resp.StatusCode == target.Response.StatusCode || (resp.StatusCode >= 200 && resp.StatusCode < 400) {
			// 成功，尝试更大的值
			maxFound = mid
			left = mid + 1
		} else if resp.StatusCode == 400 || resp.StatusCode == 431 || resp.StatusCode == 413 {
			// 请求头过多，尝试更小的值
			right = mid - 1
		} else {
			// 其他错误，使用当前值
			break
		}
	}

	return maxFound
}

// CheckMaxReqHeaderNum 检查最大支持的响应头数量
func CheckMaxReqHeaderNum(target *models.TargetStruct) (maxNum int) {
	// 基础请求头数量，1024个
	baseNum := len(models.Config.Headers)
	baseHeaders := GetRandomHeaderAndRandomValue(baseNum)
	for {
		baseNum = baseNum / 2
		if baseNum == 1 {
			return
		}
		tmpReq, err := GetSourceRequestWithCacheKey(target)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return
		}
		for headerName, value := range baseHeaders {
			tmpReq.Header.Add(headerName, value)
		}
		resp, err := utils.CommonClient.Do(tmpReq)
		if err != nil {
			continue
		}
		statusMatch := resp.StatusCode == target.Response.StatusCode
		utils.CloseReader(resp.Body)
		if statusMatch {
			return baseNum
		}
	}
}

func GetRandomHeaderAndRandomValue(num int) map[string]string {
	headers := make(map[string]string)
	for range num {
		headers[utils.RandomString(5)] = utils.RandomString(5)
	}
	return headers
}

// GroupSlice 切片按照数量分组
func GroupSlice(slice []string, groupSize int) [][]string {
	var groups [][]string
	for i := 0; i < len(slice); i += groupSize {
		end := i + groupSize
		if end > len(slice) {
			end = len(slice)
		}
		groups = append(groups, slice[i:end])
	}
	return groups
}

// findVulnerability 二分法检查是否存在漏洞和异常状态码（增强版：添加持久性验证）
func (h *HeaderCP) findVulnerability(target *models.TargetStruct, headers []string, wg *sync.WaitGroup) {
	defer wg.Done()

	// 创建唯一标记用于追踪
	marker := "wcpvs-" + utils.RandomString(8)
	pvMap := make(map[string]string)
	for _, header := range headers {
		pvMap[header] = marker + "-" + utils.RandomString(5)
	}

	var resp *http.Response
	var err error
	for range 3 {
		resp, err = GetResp(target, HEADER, pvMap)
		if err == nil {
			break
		}
	}
	if err != nil || resp == nil {
		if err != nil {
			gologger.Error().Msgf("HCP scan failed for %s after 3 retries: %v", target.Request.URL, err)
		} else {
			gologger.Error().Msgf("HCP scan returned nil response for %s", target.Request.URL)
		}
		return
	}
	defer utils.CloseReader(resp.Body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}

	// 如果响应码异常，判断此异常状态是否存在缓存机制，如果存在则缓存投毒漏洞
	if resp.StatusCode != target.Response.StatusCode {
		mid := len(headers) / 2
		leftPart := headers[:mid]
		rightPart := headers[mid:]

		if len(headers) == 1 {
			// 验证是否被缓存
			if !utils.IsCacheHit(target, &resp.Header) {
				return
			}

			// 关键：验证持久性
			isPersistent := h.verifyPersistence(target, marker)
			if !isPersistent {
				return
			}

			// 确认为漏洞
			h.RWLock.Lock()
			h.HcpParams[target.Request.URL.String()] = append(h.HcpParams[target.Request.URL.String()], maps.Keys(pvMap)...)
			h.RWLock.Unlock()

			// 输出详细的漏洞报告
			h.reportVulnerability(target, pvMap, resp, respBody, "status_change", isPersistent)
			return
		}
		wg.Add(2)
		go h.findVulnerability(target, leftPart, wg)
		go h.findVulnerability(target, rightPart, wg)
		return
	}

	if resp.StatusCode == target.Response.StatusCode {
		// 判断Body中是否存在某些字符串（反射）
		hasReflection := false
		for header, value := range pvMap {
			if strings.Contains(string(respBody), "<"+value) || strings.Contains(string(respBody), value) {
				// 检查是否被缓存
				if utils.IsCacheHit(target, &resp.Header) {
					// 验证持久性
					if h.verifyPersistence(target, marker) {
						// 输出详细的漏洞报告
						vulnMap := map[string]string{header: value}
						h.reportVulnerability(target, vulnMap, resp, respBody, "body_reflection", true)
						hasReflection = true
					}
				}
				break
			}
		}

		// 判断Header中是否存在反射
		if !hasReflection {
			for header, value := range pvMap {
				if resp.Header.Get(value) != "" {
					if utils.IsCacheHit(target, &resp.Header) {
						if h.verifyPersistence(target, marker) {
							// 输出详细的漏洞报告
							vulnMap := map[string]string{header: value}
							h.reportVulnerability(target, vulnMap, resp, respBody, "header_reflection", true)
						}
					}
					break
				}
			}
		}
		return
	}
}

// verifyPersistence 验证缓存投毒是否持久化（关键函数）
func (h *HeaderCP) verifyPersistence(target *models.TargetStruct, marker string) bool {
	// 等待缓存稳定
	time.Sleep(500 * time.Millisecond)

	// 发送3次不带恶意header的干净请求
	persistentCount := 0
	for i := 0; i < 3; i++ {
		cleanReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			continue
		}

		resp, err := utils.CommonClient.Do(cleanReq)
		if err != nil || resp == nil {
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		utils.CloseReader(resp.Body)
		if err != nil {
			continue
		}

		// 检查是否还能看到变化（状态码变化或marker存在）
		if resp.StatusCode != target.Response.StatusCode || strings.Contains(string(bodyBytes), marker) {
			persistentCount++
		}

		time.Sleep(200 * time.Millisecond)
	}

	// 如果3次中至少有2次看到持久化效果，确认为持久
	return persistentCount >= 2
}

// reportVulnerability 输出详细的漏洞报告
func (h *HeaderCP) reportVulnerability(target *models.TargetStruct, pvMap map[string]string,
	resp *http.Response, respBody []byte, vulnType string, persistent bool) {

	// 构建请求字符串
	testReq, err := GetSourceRequestWithCacheKey(target)
	if err != nil || testReq == nil {
		// Fallback: 使用原始请求
		testReq, _ = utils.CloneRequest(target.Request)
	}
	if testReq != nil {
		for k, v := range pvMap {
			testReq.Header.Set(k, v)
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
	if target.Cache.CKisCookie && len(target.Cache.CookieCacheKeys) > 0 {
		cacheKeys = append(cacheKeys, "Cookie: "+target.Cache.CookieCacheKeys[0])
	}

	// 确定攻击向量描述
	var attackVector string
	var impact string
	var reflectedContent string

	switch vulnType {
	case "status_change":
		attackVector = fmt.Sprintf("Injecting header %v causes abnormal status code %d", maps.Keys(pvMap), resp.StatusCode)
		impact = "All users will receive error response, causing service disruption (CPDoS)"
	case "body_reflection":
		attackVector = fmt.Sprintf("Header %v reflected in response body", maps.Keys(pvMap))
		impact = "Potential XSS attack - malicious script can be cached and served to all users"
		for _, v := range pvMap {
			reflectedContent = v
			break
		}
	case "header_reflection":
		attackVector = fmt.Sprintf("Header %v reflected in response headers", maps.Keys(pvMap))
		impact = "Potential header injection - can manipulate cached response headers for all users"
		for _, v := range pvMap {
			reflectedContent = v
			break
		}
	}

	// 格式化请求和响应
	reqStr := output.FormatRequest(testReq, maps.Keys(pvMap))
	bodySnippet := output.ExtractBodySnippet(respBody, 300)
	respStr := output.FormatResponse(resp, bodySnippet, reflectedContent)

	// 创建漏洞报告
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityCritical,
		Type:         output.VulnTypeHCP,
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: attackVector,
		Request:      reqStr,
		Response:     respStr,
		Impact:       impact,
		Persistent:   persistent,
		Remediation: []string{
			fmt.Sprintf("Add %v to the cache key configuration", maps.Keys(pvMap)),
			"Validate and sanitize all forwarded headers",
			"Implement strict input validation on proxy headers",
			"Consider implementing Content Security Policy (CSP)",
		},
	}

	// 输出报告
	report.Print()
}
