package tecniques

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"net/http"
	"testing"
)

func TestGetResp(t *testing.T) {
	url1 := "https://digitalvolvo.com/pc/environment.js"
	//url2 := "https://www.bilibili.com/index.html"
	resp1, _ := http.Get(url1)
	//resp2, _ := http.Get(url2)
	target1 := &models.TargetStruct{
		Request:  resp1.Request,
		Response: resp1,
		Cache:    &models.CacheStruct{},
	}
	//target2 := &internal.TargetStruct{
	//	Request:  resp2.Request,
	//	Response: resp2,
	//	Cache:    &internal.CacheStruct{},
	//}
	//targets := []*internal.TargetStruct{target1, target2}
	err := logic.Checker.Check(target1)
	if err != nil {
		return
	}
	//logic.CacheKeysFinder.FindCacheByHeader(target1)
	logic.CacheKeysFinder.FindCacheKeyByGet(target1)

	resp11, err := GetResp(target1, HEADER, map[string]string{"Test": utils.RandomString(10000)})
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	for h, v := range resp11.Header {
		fmt.Println(h, v)
	}
}
