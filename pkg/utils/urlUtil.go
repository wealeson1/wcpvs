package utils

import (
	"net/url"
	"path"
	"sort"
)

// removeURLParams 去掉URL中的参数
func removeURLParams(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	parsedURL.RawQuery = "" // 移除参数
	return parsedURL.String(), nil
}

// filterStaticFiles 在一个目录中只保留一种类型的静态文件
func filterStaticFiles(urls []string) []string {
	fileTypeMap := make(map[string]bool)
	filteredURLs := []string{}

	for _, u := range urls {
		dir := path.Dir(u)

		if !fileTypeMap[dir] {
			filteredURLs = append(filteredURLs, u)
			fileTypeMap[dir] = true
		}
	}

	return filteredURLs
}

// removeDuplicatesAndParams 处理URL列表，移除参数并去重
func RemoveDuplicatesAndParams(urls []string) ([]string, error) {
	urlMap := make(map[string]bool)
	uniqueURLs := []string{}

	for _, u := range urls {
		processedURL, err := removeURLParams(u)
		if err != nil {
			return nil, err
		}

		if !urlMap[processedURL] {
			uniqueURLs = append(uniqueURLs, processedURL)
			urlMap[processedURL] = true
		}
	}

	// 按照目录过滤，只保留一种类型的静态文件
	filteredURLs := filterStaticFiles(uniqueURLs)

	// 对结果排序，方便查看
	sort.Strings(filteredURLs)

	return filteredURLs, nil
}

//func main() {
//	urls := []string{
//		"https://example.com/dir1/file1.css?v=123",
//		"https://example.com/dir1/file2.js?v=456",
//		"https://example.com/dir2/file3.jpg",
//		"https://example.com/dir2/file4.png",
//		"https://example.com/dir3/file5.html",
//		"https://example.com/dir3/file6.html?version=1.0",
//	}
//
//	result, err := removeDuplicatesAndParams(urls)
//	if err != nil {
//		fmt.Println("Error:", err)
//		return
//	}
//
//	for _, u := range result {
//		fmt.Println(u)
//	}
//}
