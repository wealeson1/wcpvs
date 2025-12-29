package cpdos

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"golang.org/x/exp/maps"
)

type Hmo struct {
	values  []string
	headers []string
}

var HMOTecniques *Hmo

func init() {
	HMOTecniques = NewHmo()
}

func NewHmo() *Hmo {
	return &Hmo{
		values:  []string{"GET", "POST", "DELETE", "HEAD", "OPTIONS", "CONNECT", "PATCH", "PUT", "TRACE", "NONSENSE"},
		headers: []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"},
	}
}

func (h *Hmo) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}

	// 创建验证器
	verifier := utils.NewPoisoningVerifier()

	// 测试不同的method override组合
	for _, value := range h.values {
		// 构建payloadMap（所有headers都设置为相同的method）
		payloadMap := make(map[string]string)
		for _, header := range h.headers {
			payloadMap[header] = value
		}

		// 创建攻击请求（带Method Override headers）
		attackReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			gologger.Error().Msgf("HMO: Failed to clone request: %v", err)
			continue
		}
		for header, val := range payloadMap {
			attackReq.Header.Set(header, val)
		}

		// 创建验证请求（不带Method Override headers）
		verifyReq, err := utils.CloneRequest(target.Request)
		if err != nil {
			continue
		}

		// 使用验证框架验证
		result, err := verifier.Verify(target, attackReq, verifyReq)
		if err != nil {
			gologger.Debug().Msgf("HMO verification failed for method %s: %v", value, err)
			continue
		}

		// 检查是否存在漏洞
		if result.IsVulnerable {
			// 直接使用验证框架保存的body
			respBody := result.VerifyBody

			// 输出详细报告
			payloadInfo := fmt.Sprintf("Method Override Headers: %v", maps.Keys(payloadMap))
			attackVector := fmt.Sprintf("HTTP Method Override via headers %v causes error", maps.Keys(payloadMap))
			ReportCPDoSVulnerability(target, output.VulnTypeCPDoSHMO, attackVector, 
				result.VerifyResp, respBody, attackReq, payloadInfo)
			
			gologger.Debug().Msgf("HMO poisoning verified in %v (method: %s, attack: %d, verify: %d)", 
				result.TotalTime, value, result.AttackStatus, result.VerifyStatus)
			return
		}
	}
}
