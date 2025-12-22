package utils

import (
	"bufio"
	"io"
	"os"
)

// ReadFileToSlice 读取文件的每行，返回一个[]string
// @param path string 待读取文件路径
// @return result []string 读取的内容
// @return err error 错误类型
func ReadFileToSlice(path string) (result []string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer CloseReader(file)
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		result = append(result, scanner.Text())
	}
	return result, nil
}

// CloseReader 关闭Reader，忽略错误（因为在大多数情况下关闭错误是良性的）
func CloseReader(c io.ReadCloser) {
	if c != nil {
		_ = c.Close() // 忽略错误，避免程序崩溃
	}
}
