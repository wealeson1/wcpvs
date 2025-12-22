package utils

import (
	"net/http"
	"strings"
)

// DetectCDNType 检测CDN类型
func DetectCDNType(resp *http.Response) string {
	if resp == nil {
		return "Unknown"
	}

	headers := resp.Header

	// Cloudflare
	if headers.Get("CF-Cache-Status") != "" || headers.Get("CF-Ray") != "" {
		return "Cloudflare"
	}

	// Fastly
	if headers.Get("X-Fastly-Request-ID") != "" || headers.Get("Fastly-Debug-Digest") != "" {
		return "Fastly"
	}

	// Akamai
	if headers.Get("X-Akamai-Transformed") != "" || headers.Get("Akamai-Cache-Status") != "" {
		return "Akamai"
	}

	// CloudFront (AWS)
	if headers.Get("X-Amz-Cf-Id") != "" || headers.Get("X-Amz-Cf-Pop") != "" {
		return "AWS CloudFront"
	}

	// 阿里云CDN
	if headers.Get("X-Iinfo") != "" || headers.Get("Ali-Swift-Global-Savetime") != "" {
		return "AliCDN"
	}

	// 腾讯云CDN
	if headers.Get("X-NWS-LOG-UUID") != "" || headers.Get("X-Tencent-Request-Id") != "" {
		return "TencentCDN"
	}

	// 华为云CDN
	if headers.Get("X-HW-CDN-Request-Id") != "" {
		return "HuaweiCloudCDN"
	}

	// Google Cloud CDN
	if headers.Get("X-GUploader-UploadID") != "" || headers.Get("X-Cloud-Trace-Context") != "" {
		return "Google Cloud CDN"
	}

	// Azure CDN
	if headers.Get("X-Azure-Ref") != "" {
		return "Azure CDN"
	}

	// CDN77
	if headers.Get("X-CDN") == "CDN77" {
		return "CDN77"
	}

	// Varnish
	if headers.Get("Via") != "" && strings.Contains(strings.ToLower(headers.Get("Via")), "varnish") {
		return "Varnish"
	}

	// Nginx缓存
	if headers.Get("X-Proxy-Cache") != "" || headers.Get("X-Cache-Status") != "" {
		return "Nginx"
	}

	// 检查Server头
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "cloudflare") {
		return "Cloudflare"
	}
	if strings.Contains(server, "akamaighost") {
		return "Akamai"
	}

	// 如果有Age头，可能是origin缓存
	if headers.Get("Age") != "" {
		return "Generic Cache"
	}

	return "Unknown"
}
