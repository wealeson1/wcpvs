package tecniques

import (
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

// CacheProbing 缓存探测技术
// 通过响应时间和header差异等侧信道信息探测缓存
type CacheProbing struct {
	// 采样次数
	SampleCount int
	// 时间差异阈值（毫秒）
	TimingThreshold float64
}

var CacheProbingTechniques *CacheProbing

func init() {
	CacheProbingTechniques = NewCacheProbing()
}

func NewCacheProbing() *CacheProbing {
	return &CacheProbing{
		SampleCount:     10, // 采样10次
		TimingThreshold: 100.0, // 100ms差异阈值
	}
}

// Scan 执行缓存探测扫描
func (c *CacheProbing) Scan(target *models.TargetStruct) {
	// 这个技术主要用于辅助缓存检测，不单独作为漏洞报告
	// 检测结果仅记录在Debug日志中，不输出报告
	
	gologger.Debug().Msgf("CacheProbing: Starting timing analysis for %s", target.Request.URL)

	// 1. 时间分析
	timingResult := c.timingAnalysis(target)
	
	// 2. Header差异分析
	headerResult := c.headerDifferenceAnalysis(target)
	
	// 3. 内容变化分析
	contentResult := c.contentChangeAnalysis(target)

	// 仅记录Debug日志，不生成报告
	if timingResult || headerResult || contentResult {
		gologger.Debug().Msgf("CacheProbing: Cache detected for %s (Timing: %v, Header: %v, Content: %v)", 
			target.Request.URL, timingResult, headerResult, contentResult)
	}
}

// timingAnalysis 响应时间分析
func (c *CacheProbing) timingAnalysis(target *models.TargetStruct) bool {
	gologger.Debug().Msgf("CacheProbing: Performing timing analysis")

	var timings []float64

	// 采样多次请求的响应时间
	for i := 0; i < c.SampleCount; i++ {
		req, err := utils.CloneRequest(target.Request)
		if err != nil {
			continue
		}

		// 添加cache-busting参数，确保第一次是miss
		if i == 0 {
			q := req.URL.Query()
			q.Set("_cache_bust", utils.RandomString(8))
			req.URL.RawQuery = q.Encode()
		}

		start := time.Now()
		resp, err := utils.CommonClient.Do(req)
		elapsed := time.Since(start).Milliseconds()

		if err != nil || resp == nil {
			continue
		}

		// 读取并丢弃body（确保完整接收）
		_, _ = io.ReadAll(resp.Body)
		utils.CloseReader(resp.Body)

		timings = append(timings, float64(elapsed))

		// 短暂延迟，避免请求过快
		time.Sleep(100 * time.Millisecond)
	}

	if len(timings) < 3 {
		return false
	}

	// 分析时间分布
	return c.analyzeTimingDistribution(timings)
}

// analyzeTimingDistribution 分析时间分布
func (c *CacheProbing) analyzeTimingDistribution(timings []float64) bool {
	if len(timings) == 0 {
		return false
	}

	// 计算统计值
	mean := c.calculateMean(timings)
	stdDev := c.calculateStdDev(timings, mean)

	gologger.Debug().Msgf("CacheProbing: Timing stats - Mean: %.2fms, StdDev: %.2fms", mean, stdDev)

	// 检查是否存在明显的两组分布（miss vs hit）
	// 第一次请求（cache miss）应该明显慢于后续请求（cache hit）
	if len(timings) > 0 && timings[0] > mean+stdDev && stdDev > c.TimingThreshold {
		gologger.Debug().Msgf("CacheProbing: Detected timing difference - first request: %.2fms, mean: %.2fms", timings[0], mean)
		return true
	}

	return false
}

// headerDifferenceAnalysis Header差异分析
func (c *CacheProbing) headerDifferenceAnalysis(target *models.TargetStruct) bool {
	gologger.Debug().Msgf("CacheProbing: Analyzing header differences")

	// 发送两次请求，观察header变化
	req1, _ := utils.CloneRequest(target.Request)
	resp1, err := utils.CommonClient.Do(req1)
	if err != nil || resp1 == nil {
		return false
	}
	utils.CloseReader(resp1.Body)

	// 等待一小段时间
	time.Sleep(1 * time.Second)

	req2, _ := utils.CloneRequest(target.Request)
	resp2, err := utils.CommonClient.Do(req2)
	if err != nil || resp2 == nil {
		return false
	}
	utils.CloseReader(resp2.Body)

	// 检查关键header的变化
	cacheHeaders := []string{"X-Cache", "X-Cache-Hits", "X-Iinfo", "Age", "CF-Cache-Status"}
	
	headerChanged := false
	for _, header := range cacheHeaders {
		val1 := resp1.Header.Get(header)
		val2 := resp2.Header.Get(header)

		if val1 != "" && val2 != "" && val1 != val2 {
			gologger.Debug().Msgf("CacheProbing: Header %s changed: %s -> %s", header, val1, val2)
			headerChanged = true
		}
	}

	// 特别检查Age header的增长
	age1 := resp1.Header.Get("Age")
	age2 := resp2.Header.Get("Age")
	if age1 != "" && age2 != "" && age2 > age1 {
		gologger.Debug().Msgf("CacheProbing: Age header increased: %s -> %s", age1, age2)
		return true
	}

	return headerChanged
}

// contentChangeAnalysis 内容变化分析
func (c *CacheProbing) contentChangeAnalysis(target *models.TargetStruct) bool {
	gologger.Debug().Msgf("CacheProbing: Analyzing content stability")

	// 发送多次请求，检查内容是否完全相同
	var bodies [][]byte

	for i := 0; i < 3; i++ {
		req, _ := utils.CloneRequest(target.Request)
		resp, err := utils.CommonClient.Do(req)
		if err != nil || resp == nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		utils.CloseReader(resp.Body)
		if err != nil {
			continue
		}

		bodies = append(bodies, body)
		time.Sleep(500 * time.Millisecond)
	}

	if len(bodies) < 3 {
		return false
	}

	// 比较内容是否完全相同
	allSame := true
	for i := 1; i < len(bodies); i++ {
		if len(bodies[i]) != len(bodies[0]) {
			allSame = false
			break
		}
	}

	if allSame {
		gologger.Debug().Msgf("CacheProbing: Content is stable (likely cached)")
		return true
	}

	return false
}

// reportCacheDetection 报告缓存检测结果
func (c *CacheProbing) reportCacheDetection(target *models.TargetStruct, timingDetected, headerDetected, contentDetected bool) {
	// 构建检测方法描述
	detectionMethods := []string{}
	if timingDetected {
		detectionMethods = append(detectionMethods, "Timing analysis (response time difference)")
	}
	if headerDetected {
		detectionMethods = append(detectionMethods, "Header difference analysis")
	}
	if contentDetected {
		detectionMethods = append(detectionMethods, "Content stability analysis")
	}

	if len(detectionMethods) == 0 {
		return
	}

	methodsStr := ""
	for i, method := range detectionMethods {
		methodsStr += fmt.Sprintf("  %d. %s\n", i+1, method)
	}

	// 构建请求
	testReq, _ := utils.CloneRequest(target.Request)

	// 提取缓存键
	cacheKeys := []string{}
	if target.Cache.CKIsGet {
		cacheKeys = append(cacheKeys, target.Cache.GetCacheKeys...)
	}
	if target.Cache.CKIsHeader {
		cacheKeys = append(cacheKeys, target.Cache.HeaderCacheKeys...)
	}

	// 格式化请求
	payloadInfo := fmt.Sprintf("Cache detected via side-channel analysis:\n%s", methodsStr)
	reqStr := output.FormatRequestSimple(testReq, payloadInfo)

	// 创建信息报告（不是漏洞，只是信息）
	report := &output.VulnerabilityReport{
		Severity:     output.SeverityMedium,
		Type:         "Cache Detection via Side-Channel (Info)",
		Target:       target.Request.URL.String(),
		CDN:          utils.DetectCDNType(target.Response),
		CacheKeys:    cacheKeys,
		AttackVector: "Side-channel analysis reveals caching behavior through timing, headers, and content stability",
		Request:      reqStr,
		Response:     fmt.Sprintf("Detection methods used:\n%s", methodsStr),
		Impact:       "Cache behavior can be probed via side-channel - useful for cache poisoning reconnaissance",
		Persistent:   false,
		Remediation: []string{
			"This is informational - cache probing enables other attacks",
			"Implement consistent response times to prevent timing analysis",
			"Minimize cache-related header exposure",
			"Consider rate limiting to slow down probing",
		},
	}

	// 输出报告
	report.Print()
}

// 统计辅助函数
func (c *CacheProbing) calculateMean(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}

	sum := 0.0
	for _, val := range data {
		sum += val
	}
	return sum / float64(len(data))
}

func (c *CacheProbing) calculateStdDev(data []float64, mean float64) float64 {
	if len(data) == 0 {
		return 0
	}

	variance := 0.0
	for _, val := range data {
		diff := val - mean
		variance += diff * diff
	}
	variance /= float64(len(data))

	return math.Sqrt(variance)
}

func (c *CacheProbing) calculateMedian(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}

	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

