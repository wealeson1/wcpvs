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

// CloseReader 关闭Read，如果存在错误使程序崩溃
func CloseReader(c io.ReadCloser) {
	err := c.Close()
	if err != nil {
		panic(err)
	}
}
