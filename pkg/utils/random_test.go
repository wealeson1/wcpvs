package utils

import (
	"fmt"
	"testing"
)

func TestRandomString(t *testing.T) {
	randomString := RandomString(8192)
	if len(randomString) != 8192 {
		t.Errorf("random string length should be 1024")
	}
	fmt.Println(randomString)
}
