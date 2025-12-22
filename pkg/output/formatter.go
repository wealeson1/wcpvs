package output

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// FormatRequest 格式化HTTP请求，高亮payload
func FormatRequest(req *http.Request, payloadHeaders []string) string {
	if req == nil {
		return "Request is nil"
	}

	var buf bytes.Buffer

	// 请求行
	buf.WriteString(fmt.Sprintf("%s %s %s\n", req.Method, req.URL.RequestURI(), req.Proto))

	// Host header (单独处理)
	buf.WriteString(fmt.Sprintf("Host: %s\n", req.Host))

	// 其他headers
	for name, values := range req.Header {
		if strings.EqualFold(name, "Host") {
			continue // 已经处理过了
		}
		
		for _, value := range values {
			isPayload := contains(payloadHeaders, name)
			if isPayload {
				buf.WriteString(fmt.Sprintf("%s: %s [PAYLOAD] ⚠️\n", name, value))
			} else {
				// 只显示关键的headers
				if isImportantHeader(name) {
					buf.WriteString(fmt.Sprintf("%s: %s\n", name, value))
				}
			}
		}
	}

	// Cookies (如果存在)
	if len(req.Cookies()) > 0 {
		buf.WriteString("\nCookies:\n")
		for _, cookie := range req.Cookies() {
			buf.WriteString(fmt.Sprintf("  %s=%s\n", cookie.Name, cookie.Value))
		}
	}

	// Body (如果存在且可读)
	if req.Body != nil && req.ContentLength > 0 {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil && len(bodyBytes) > 0 {
			// 恢复Body以便后续使用
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			
			buf.WriteString("\n")
			// 限制body长度
			if len(bodyBytes) > 200 {
				buf.WriteString(string(bodyBytes[:200]) + "... [truncated]")
			} else {
				buf.WriteString(string(bodyBytes))
			}
		}
	}

	return buf.String()
}

// FormatResponse 格式化HTTP响应，高亮反射点
func FormatResponse(resp *http.Response, bodySnippet string, reflectedContent string) string {
	if resp == nil {
		return "Response is nil"
	}

	var buf bytes.Buffer

	// 状态行
	buf.WriteString(fmt.Sprintf("%s %s\n", resp.Proto, resp.Status))

	// 重要的headers
	importantHeaders := []string{"X-Cache", "X-Cache-Hits", "X-Iinfo", "Age", "CF-Cache-Status", 
		"Server", "Content-Type", "Content-Length", "Cache-Control", "Expires"}
	
	for _, name := range importantHeaders {
		if values, ok := resp.Header[name]; ok {
			for _, value := range values {
				buf.WriteString(fmt.Sprintf("%s: %s\n", name, value))
			}
		}
	}

	// Body snippet (如果提供)
	if bodySnippet != "" {
		buf.WriteString("\nBody:\n")
		if reflectedContent != "" {
			// 高亮反射的内容
			highlighted := strings.ReplaceAll(bodySnippet, reflectedContent, 
				fmt.Sprintf("%s [REFLECTED] 🔴", reflectedContent))
			buf.WriteString(highlighted)
		} else {
			buf.WriteString(bodySnippet)
		}
	}

	return buf.String()
}

// FormatRequestSimple 简化的请求格式化（只显示最关键信息）
func FormatRequestSimple(req *http.Request, payloadInfo string) string {
	if req == nil {
		return "Request is nil"
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s %s\n", req.Method, req.URL.String()))
	
	if payloadInfo != "" {
		buf.WriteString(fmt.Sprintf("Payload: %s ⚠️\n", payloadInfo))
	}

	return buf.String()
}

// FormatResponseSimple 简化的响应格式化
func FormatResponseSimple(resp *http.Response, cacheStatus string) string {
	if resp == nil {
		return "Response is nil"
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("Status: %s\n", resp.Status))
	
	if cacheStatus != "" {
		buf.WriteString(fmt.Sprintf("Cache: %s\n", cacheStatus))
	}

	return buf.String()
}

// isImportantHeader 判断是否为重要的header
func isImportantHeader(name string) bool {
	importantHeaders := []string{
		"User-Agent", "Accept", "Accept-Encoding", "Accept-Language",
		"Content-Type", "Content-Length", "Connection", "Cookie",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL",
	}

	nameLower := strings.ToLower(name)
	for _, h := range importantHeaders {
		if strings.ToLower(h) == nameLower {
			return true
		}
	}
	return false
}

// contains 检查字符串切片是否包含指定字符串（不区分大小写）
func contains(slice []string, str string) bool {
	strLower := strings.ToLower(str)
	for _, s := range slice {
		if strings.ToLower(s) == strLower {
			return true
		}
	}
	return false
}

// GetCacheStatus 从响应中提取缓存状态
func GetCacheStatus(resp *http.Response) string {
	if resp == nil {
		return "Unknown"
	}

	// 检查各种缓存header
	if cache := resp.Header.Get("X-Cache"); cache != "" {
		return cache
	}
	if cache := resp.Header.Get("CF-Cache-Status"); cache != "" {
		return cache
	}
	if cache := resp.Header.Get("X-Cache-Hits"); cache != "" {
		return fmt.Sprintf("Hits: %s", cache)
	}
	if age := resp.Header.Get("Age"); age != "" {
		return fmt.Sprintf("Age: %s", age)
	}

	return "Unknown"
}

// ExtractBodySnippet 提取响应体的片段（用于显示）
func ExtractBodySnippet(body []byte, maxLength int) string {
	if len(body) == 0 {
		return ""
	}

	if maxLength <= 0 {
		maxLength = 300
	}

	bodyStr := string(body)
	if len(bodyStr) > maxLength {
		return bodyStr[:maxLength] + "... [truncated]"
	}

	return bodyStr
}

