package logic

import (
	"github.com/wealeson1/wcpvs/internal"
	"net/http"
	"testing"
)

func TestNewCheckCache(t *testing.T) {
	url1 := "https://lf3-cdn-tos.bytegoofy.com/obj/goofy/ies/douyin_web/polyfill.9f1198a1.js"
	url2 := "https://digitalvolvo.com/opensso-login/js/jquery.min.js"
	resp1, _ := http.Get(url1)
	resp2, _ := http.Get(url2)
	target1 := internal.TargetStruct{
		Request:  resp1.Request,
		Response: resp1,
		Cache:    &internal.CacheStruct{},
	}
	target2 := internal.TargetStruct{
		Request:  resp2.Request,
		Response: resp2,
		Cache:    &internal.CacheStruct{},
	}
	targets := []*internal.TargetStruct{&target1, &target2}
	checkCache := NewCheckCache(targets)
	_, err := checkCache.Run()
	if err != nil {
		return
	}

}
