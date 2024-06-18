package dos

import (
	"github.com/wealeson1/wcpvs/internal"
	"github.com/wealeson1/wcpvs/internal/logic"
	"net/http"
	"testing"
)

func TestHHO_Scan(t *testing.T) {
	url1 := "https://digitalvolvo.com/pc/environment.js"
	url2 := "https://www.bilibili.com/index.html"
	resp1, _ := http.Get(url1)
	resp2, _ := http.Get(url2)
	target1 := &internal.TargetStruct{
		Request:  resp1.Request,
		Response: resp1,
		Cache:    &internal.CacheStruct{},
	}
	target2 := &internal.TargetStruct{
		Request:  resp2.Request,
		Response: resp2,
		Cache:    &internal.CacheStruct{},
	}
	targets := []*internal.TargetStruct{target1, target2}
	err := logic.Checker.Check(targets)
	if err != nil {
		return
	}
	//logic.CacheKeysFinder.FindCacheByHeader(target1)
	err = logic.CacheKeysFinder.Check(targets)
	if err != nil {
		return
	}
	HHOTecnique.Scan(target1)
}
