package cpdos

import (
	"github.com/wealeson1/wcpvs/internal/logic"
	"github.com/wealeson1/wcpvs/internal/models"
	"net/http"
	"testing"
)

func TestHHO_Scan(t *testing.T) {
	url1 := "https://0abb001703d7090681ad8efd00b300b4.web-security-academy.net/"
	//url2 := "https://www.bilibili.com/index.html"
	_, err := http.Get(url1)
	if err != nil {
		t.Fatal(err)
	}

	resp2, _ := http.Get(url1)
	target1 := &models.TargetStruct{
		Request:  resp2.Request,
		Response: resp2,
		Cache:    &models.CacheStruct{},
	}
	//target2 := &internal.TargetStruct{
	//	Request:  resp2.Request,
	//	Response: resp2,
	//	Cache:    &internal.CacheStruct{},
	//}
	//targets := []*internal.TargetStruct{target1, target2}
	err = logic.Checker.Check(target1)
	if err != nil {
		return
	}
	err = logic.CacheKeysFinder.Check(target1)
	//err = logic.CacheKeysFinder.FindCacheKeyByGet(target1)
	if err != nil {
		return
	}
	HHOTecnique.Scan(target1)
}
