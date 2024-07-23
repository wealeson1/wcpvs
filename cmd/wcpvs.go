package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/internal/runner"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"sync"
)

func main() {
	// 确保 ScanOptions 已经被正确初始化
	if runner.ScanOptions == nil {
		panic("ScanOptions is not initialized")
	}
	// 默认线程数
	threadCount := runner.ScanOptions.Threads
	var wg sync.WaitGroup
	var TargetsChannel = make(chan *models.TargetStruct, 1000000)
	// 启动工作goroutine
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				target, ok := <-TargetsChannel
				if !ok {
					return
				}
				runner.Run(target)
			}
		}()
	}

	for _, url := range runner.ScanOptions.Urls {
		if resp, err := utils.CommonClient.Get(url); err != nil || resp.StatusCode > 400 {
			continue
		}
		if !runner.ScanOptions.Crawler {
			primitiveResp, err := utils.CommonClient.Get(url)
			if err != nil || primitiveResp == nil {
				continue
			}
			respBody, err := io.ReadAll(primitiveResp.Body)
			if err != nil {
				gologger.Error().Msg("wcpvs.main:" + err.Error())
				continue
			}
			utils.CloseReader(primitiveResp.Body)
			target := &models.TargetStruct{
				Request:  primitiveResp.Request,
				Response: primitiveResp,
				RespBody: respBody,
				Cache: &models.CacheStruct{
					NoCache: true,
				},
			}
			TargetsChannel <- target
		} else {
			runner.Crawl(url, TargetsChannel)
		}
	}

	// 通知所有goroutine任务已完成
	close(TargetsChannel)
	wg.Wait()
}
