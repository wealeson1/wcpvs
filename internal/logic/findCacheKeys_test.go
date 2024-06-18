package logic

import (
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"testing"
)

func TestNewCheckCache(t *testing.T) {
	url1 := "https://0ac0007e0322610b80c61cb0006400b0.web-security-academy.net/"
	//url2 := "https://0aac00b403e73d9e82310772009400d7.web-security-academy.net/resources/js/tracking.js"
	// target必须是两个请求的后一个
	_, err := utils.CommonClient.Get(url1)
	if err != nil {
		t.Error(err)
	}
	resp3, _ := utils.CommonClient.Get(url1)
	//resp2, _ := http.Get(url2)

	target1 := &models.TargetStruct{
		Request:  resp3.Request,
		Response: resp3,
		Cache:    &models.CacheStruct{},
	}
	//target2 := internal.TargetStruct{
	//	Request:  resp2.Request,
	//	Response: resp2,
	//	Cache:    &internal.CacheStruct{},
	//}
	targets := []*models.TargetStruct{target1}
	err = Checker.Check(targets[0])
	if err != nil {
		t.Error(err)
	}
	err = CacheKeysFinder.Check(target1)
	if err != nil {
		t.Error(err)
	}
}
