package output

import "strings"

// 边框样式常量
const (
	// Unicode边框字符
	TopLeftCorner     = "╔"
	TopRightCorner    = "╗"
	BottomLeftCorner  = "╚"
	BottomRightCorner = "╝"
	HorizontalLine    = "═"
	VerticalLine      = "║"
	LeftTee           = "╠"
	RightTee          = "╣"

	// 简单边框
	SideBorder = "║"
)

// TopBorder 生成顶部边框
func TopBorder(length int) string {
	return TopLeftCorner + strings.Repeat(HorizontalLine, length-2) + TopRightCorner
}

// BottomBorder 生成底部边框
func BottomBorder(length int) string {
	return BottomLeftCorner + strings.Repeat(HorizontalLine, length-2) + BottomRightCorner
}

// MiddleBorder 生成中间分隔线
func MiddleBorder(length int) string {
	return LeftTee + strings.Repeat(HorizontalLine, length-2) + RightTee
}

// Emoji图标常量
const (
	IconCritical     = "🔴"
	IconHigh         = "🟠"
	IconMedium       = "🟡"
	IconLow          = "🟢"
	IconSuccess      = "✓"
	IconFailure      = "✗"
	IconScanning     = "🔍"
	IconRequest      = "📦"
	IconResponse     = "📥"
	IconImpact       = "💥"
	IconRemediation  = "🛡️"
	IconTarget       = "🎯"
	IconCache        = "🔑"
	IconAttack       = "⚔️"
	IconWarning      = "⚠️"
	IconProcessing   = "⏳"
	IconRocket       = "🚀"
)

// 严重程度常量
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// 漏洞类型常量
const (
	VulnTypeHCP         = "Header Cache Poisoning"
	VulnTypeParameterCP = "Parameter Cache Poisoning"
	VulnTypeCookieCP    = "Cookie Cache Poisoning"
	VulnTypeFatGet      = "Fat GET"
	VulnTypeCPDoSHHO    = "CPDoS (HHO - Huge Headers)"
	VulnTypeCPDoSHMO    = "CPDoS (HMO - Huge Method)"
	VulnTypeCPDoSHMC    = "CPDoS (HMC - Huge Meta-Character)"
	VulnTypeCPDoSBLCP   = "CPDoS (BLCP - Big Line CR/LF)"
	VulnTypeCPDoSHHCN   = "CPDoS (HHCN - Huge Header Count)"
	VulnTypeCPDoSPNC    = "CPDoS (PNC - Path Normalization Conflict)"
	VulnTypeCPDoSRDD    = "CPDoS (RDD - Range Delimiter Duplication)"
	VulnTypeCPDoSUPC    = "CPDoS (UPC - Unkeyed Port in Cache)"
)

