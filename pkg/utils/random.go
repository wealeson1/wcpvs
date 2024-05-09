package utils

import (
	"crypto/rand"
	"math/big"
)

// RandomString 生成一个指定长度的随机字符串
// @param len int  指定生成随机数的长度
// @return  string 返回生成的随机字符串，长度为 param len
func RandomString(length int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	randStr := make([]byte, length)
	for i := range randStr {
		// 生成一个 [0, len(letters)-1] 范围内的安全随机数
		randNum, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters)-1)))
		if err != nil {
			panic(err)
		}
		// 使用生成的随机数作为索引从letters字符串中选择字符
		randStr[i] = letters[randNum.Int64()]
	}
	return string(randStr)
}

// RandInt64 生成一个安全的随机 int64 值。
// @param nil
// @return int64 返回生成的随机int64
func RandInt64() int64 {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(int64(1e18)))
	if err != nil {
		panic(err)
	}
	return randomInt.Int64()
}
