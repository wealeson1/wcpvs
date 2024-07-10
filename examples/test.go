package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func main() {

	fmt.Println(url.PathEscape("a"))
	resp, err := http.Get("https://www.baidu.com/asdasd/")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	tmpReq := resp.Request
	path := tmpReq.URL.Path
	if path == "" || path == "//" {
		return
	}
	// 分割路径
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 1 {
		firstSegment := pathSegments[1]
		if firstSegment == "" {
			return
		}
		encodeChar := fmt.Sprintf("%%%02x", firstSegment[0])
		pathSegments[1] = encodeChar + firstSegment[1:]
	}
	fmt.Println(pathSegments)
}

//// 用编码后的字符串替换原来的字符串
//pathSegments[1] = encodedSegment
//
//// 重新组合路径
//newPath := strings.Join(pathSegments, "/")
//tmpReq.URL.Path = newPath
//log.Printf("原始路径: %s, 新路径: %s", path, newPath)
//fmt.Println(tmpReq.URL.Path)

// CustomPathEscape 对每个字符进行百分号编码
func CustomPathEscape(s string) string {
	encoded := ""
	for _, char := range s {
		encoded += fmt.Sprintf("%%%02X", char)
	}
	return encoded
}
