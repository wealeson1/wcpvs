package utils

import (
	"io"
	"net/http"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
)

// PoisoningVerifier 统一的缓存投毒验证器
type PoisoningVerifier struct {
	WaitTime       time.Duration // 攻击后等待缓存生效的时间（默认100ms）
	VerifyRetries  int           // 验证重试次数（默认3次）
	MaxTotalTime   time.Duration // 整个验证过程的最大时间（默认1秒）
	RequireCacheHit bool          // 是否要求验证响应必须是Cache HIT（默认true）
}

// NewPoisoningVerifier 创建验证器实例
func NewPoisoningVerifier() *PoisoningVerifier {
	return &PoisoningVerifier{
		WaitTime:       100 * time.Millisecond,
		VerifyRetries:  3,
		MaxTotalTime:   1 * time.Second,
		RequireCacheHit: true,
	}
}

// VerificationResult 验证结果
type VerificationResult struct {
	IsVulnerable    bool           // 是否存在漏洞
	AttackStatus    int            // 攻击请求的状态码
	VerifyStatus    int            // 验证请求的状态码
	AttackResp      *http.Response // 攻击响应（body已关闭）
	VerifyResp      *http.Response // 验证响应（body已关闭）
	VerifyBody      []byte         // 验证响应的body（仅在IsVulnerable=true时保留）
	CacheHit        bool           // 验证请求是否命中缓存
	TotalTime       time.Duration  // 总耗时
	VerifyAttempts  int            // 验证尝试次数
}

// Verify 验证缓存投毒是否成功
// 逻辑：
// 1. 发送攻击请求（带异常payload）
// 2. 短暂等待让缓存生效
// 3. 发送正常请求验证是否受到污染
// 4. 检查验证请求是否返回了异常响应且命中缓存
func (v *PoisoningVerifier) Verify(
	target *models.TargetStruct,
	attackReq *http.Request,
	verifyReq *http.Request,
) (*VerificationResult, error) {
	startTime := time.Now()
	
	result := &VerificationResult{
		IsVulnerable: false,
	}

	// 1. 发送攻击请求
	attackResp, err := CommonClient.Do(attackReq)
	if err != nil {
		return result, err
	}
	defer CloseReader(attackResp.Body)
	
	// 读取并丢弃body（确保连接可以复用）
	_, _ = io.Copy(io.Discard, attackResp.Body)
	
	result.AttackStatus = attackResp.StatusCode
	result.AttackResp = attackResp

	// 检查是否产生了异常响应
	if attackResp.StatusCode < 300 {
		// 没有产生异常，不是漏洞
		return result, nil
	}

	// 2. 等待缓存生效
	time.Sleep(v.WaitTime)

	// 3. 验证请求（可能需要多次尝试）
	for attempt := 1; attempt <= v.VerifyRetries; attempt++ {
		result.VerifyAttempts = attempt
		
		// 检查是否超时
		if time.Since(startTime) > v.MaxTotalTime {
			gologger.Debug().Msgf("Verification timeout after %v", time.Since(startTime))
			break
		}

		// 克隆验证请求（每次重试都需要新的请求对象）
		verifyReqClone, err := CloneRequest(verifyReq)
		if err != nil {
			gologger.Error().Msgf("Failed to clone verify request: %v", err)
			continue
		}

		// 发送验证请求
		verifyResp, err := CommonClient.Do(verifyReqClone)
		if err != nil {
			gologger.Error().Msgf("Verify request failed (attempt %d): %v", attempt, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// 读取body（先保存，后面判断是否需要）
		verifyBody, readErr := io.ReadAll(verifyResp.Body)
		CloseReader(verifyResp.Body)
		if readErr != nil {
			gologger.Debug().Msgf("Failed to read verify response body: %v", readErr)
			verifyBody = []byte{}
		}

		result.VerifyStatus = verifyResp.StatusCode
		result.VerifyResp = verifyResp
		result.CacheHit = IsCacheHit(target, &verifyResp.Header)

		// 4. 判断是否被污染
		// 条件：验证请求返回了和攻击请求相同的异常状态码
		statusMatch := verifyResp.StatusCode == attackResp.StatusCode
		
		if statusMatch {
			if v.RequireCacheHit {
				// 需要验证是从缓存返回的
				if result.CacheHit {
					result.IsVulnerable = true
					result.VerifyBody = verifyBody // 保存body用于报告
					result.TotalTime = time.Since(startTime)
					return result, nil
				}
			} else {
				// 不要求Cache HIT（某些场景下缓存指示器可能不准确）
				result.IsVulnerable = true
				result.VerifyBody = verifyBody // 保存body用于报告
				result.TotalTime = time.Since(startTime)
				return result, nil
			}
		}

		// 短暂等待后重试
		if attempt < v.VerifyRetries {
			time.Sleep(100 * time.Millisecond)
		}
	}

	result.TotalTime = time.Since(startTime)
	return result, nil
}

// VerifyWithFunc 使用函数式接口验证
// attackFunc: 创建并发送攻击请求的函数
// verifyFunc: 创建并发送验证请求的函数
func (v *PoisoningVerifier) VerifyWithFunc(
	target *models.TargetStruct,
	attackFunc func() (*http.Response, error),
	verifyFunc func() (*http.Response, error),
) (*VerificationResult, error) {
	startTime := time.Now()
	
	result := &VerificationResult{
		IsVulnerable: false,
	}

	// 1. 发送攻击请求
	attackResp, err := attackFunc()
	if err != nil {
		return result, err
	}
	defer CloseReader(attackResp.Body)
	
	// 读取并丢弃body
	_, _ = io.Copy(io.Discard, attackResp.Body)
	
	result.AttackStatus = attackResp.StatusCode
	result.AttackResp = attackResp

	// 检查是否产生了异常响应（3xx, 4xx, 5xx都算异常）
	if attackResp.StatusCode < 300 {
		return result, nil
	}

	// 2. 等待缓存生效
	time.Sleep(v.WaitTime)

	// 3. 验证请求
	for attempt := 1; attempt <= v.VerifyRetries; attempt++ {
		result.VerifyAttempts = attempt
		
		// 检查超时
		if time.Since(startTime) > v.MaxTotalTime {
			break
		}

		verifyResp, err := verifyFunc()
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// 读取body
		verifyBody, readErr := io.ReadAll(verifyResp.Body)
		CloseReader(verifyResp.Body)
		if readErr != nil {
			gologger.Debug().Msgf("Failed to read verify response body: %v", readErr)
			verifyBody = []byte{}
		}

		result.VerifyStatus = verifyResp.StatusCode
		result.VerifyResp = verifyResp
		result.CacheHit = IsCacheHit(target, &verifyResp.Header)

		// 判断是否被污染
		statusMatch := verifyResp.StatusCode == attackResp.StatusCode
		
		if statusMatch {
			if v.RequireCacheHit {
				if result.CacheHit {
					result.IsVulnerable = true
					result.VerifyBody = verifyBody // 保存body
					result.TotalTime = time.Since(startTime)
					return result, nil
				}
			} else {
				result.IsVulnerable = true
				result.VerifyBody = verifyBody // 保存body
				result.TotalTime = time.Since(startTime)
				return result, nil
			}
		}

		if attempt < v.VerifyRetries {
			time.Sleep(100 * time.Millisecond)
		}
	}

	result.TotalTime = time.Since(startTime)
	return result, nil
}

// VerifyPersistence 验证持久化（用于特殊技术如Host Header Poisoning）
// 逻辑：重复发送相同的攻击请求，检查异常响应是否被缓存
func (v *PoisoningVerifier) VerifyPersistence(
	target *models.TargetStruct,
	attackReq *http.Request,
) (*VerificationResult, error) {
	startTime := time.Now()
	
	result := &VerificationResult{
		IsVulnerable: false,
	}

	// 1. 首次攻击请求
	attackResp, err := CommonClient.Do(attackReq)
	if err != nil {
		return result, err
	}
	defer CloseReader(attackResp.Body)
	_, _ = io.Copy(io.Discard, attackResp.Body)
	
	result.AttackStatus = attackResp.StatusCode

	// 检查是否产生异常
	if attackResp.StatusCode < 300 {
		return result, nil
	}

	// 2. 等待缓存生效
	time.Sleep(v.WaitTime)

	// 3. 重复相同的攻击请求，检查是否从缓存返回
	for attempt := 1; attempt <= v.VerifyRetries; attempt++ {
		result.VerifyAttempts = attempt
		
		if time.Since(startTime) > v.MaxTotalTime {
			break
		}

		// 克隆请求
		verifyReq, err := CloneRequest(attackReq)
		if err != nil {
			continue
		}

		verifyResp, err := CommonClient.Do(verifyReq)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// 读取body
		verifyBody, readErr := io.ReadAll(verifyResp.Body)
		CloseReader(verifyResp.Body)
		if readErr != nil {
			gologger.Debug().Msgf("Failed to read verify response body: %v", readErr)
			verifyBody = []byte{}
		}

		result.VerifyStatus = verifyResp.StatusCode
		result.VerifyResp = verifyResp
		result.CacheHit = IsCacheHit(target, &verifyResp.Header)

		// 判断：相同状态码 + 命中缓存
		if verifyResp.StatusCode == attackResp.StatusCode && result.CacheHit {
			result.IsVulnerable = true
			result.VerifyBody = verifyBody // 保存body
			result.TotalTime = time.Since(startTime)
			return result, nil
		}

		if attempt < v.VerifyRetries {
			time.Sleep(100 * time.Millisecond)
		}
	}

	result.TotalTime = time.Since(startTime)
	return result, nil
}

// QuickVerify 快速验证（单次尝试，用于批量测试）
func (v *PoisoningVerifier) QuickVerify(
	target *models.TargetStruct,
	attackReq *http.Request,
	verifyReq *http.Request,
) bool {
	// 使用默认配置但只尝试1次
	quickVerifier := &PoisoningVerifier{
		WaitTime:       100 * time.Millisecond,
		VerifyRetries:  1,
		MaxTotalTime:   500 * time.Millisecond,
		RequireCacheHit: true,
	}
	
	result, err := quickVerifier.Verify(target, attackReq, verifyReq)
	if err != nil {
		return false
	}
	
	return result.IsVulnerable
}

