package main

import (
	"github.com/wealeson1/wcpvs/internal/logic"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/internal/runner"
	"github.com/wealeson1/wcpvs/pkg/utils"
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
				logic.Run(target)
			}
		}()
	}

	for _, url := range runner.ScanOptions.Urls {
		if !runner.ScanOptions.Crawler {
			_, err := utils.CommonClient.Get(url)
			if err != nil {
				continue
			}
			primitiveResp, _ := utils.CommonClient.Get(url)
			if primitiveResp == nil {
				continue
			}
			target := &models.TargetStruct{
				Request:  primitiveResp.Request,
				Response: primitiveResp,
				Cache:    &models.CacheStruct{},
			}
			TargetsChannel <- target
		} else {
			logic.Crawl(url, TargetsChannel)
		}
	}

	// 通知所有goroutine任务已完成
	close(TargetsChannel)
	wg.Wait()
}
