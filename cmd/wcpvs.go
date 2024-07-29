package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/internal/runner"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"time"
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

	// 启动资源监控goroutine
	go func() {
		for {
			Monitor(os.Getpid())
			time.Sleep(10 * time.Second) // 每隔10秒打印一次监控信息
		}
	}()

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
				Cache:    &models.CacheStruct{},
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

func Monitor(pid int) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		gologger.Fatal().Msgf("Could not create process: %v", err)
		return
	}
	cpuPercent, err := p.Percent(time.Second)
	if err != nil {
		gologger.Fatal().Msgf("Could not get CPU percent: %v", err)
		return
	}
	memPercent, err := p.MemoryPercent()
	if err != nil {
		gologger.Fatal().Msgf("Could not get memory percent: %v", err)
		return
	}
	cp := cpuPercent / float64(runtime.NumCPU())
	threadCount := pprof.Lookup("threadcreate").Count()
	gNum := runtime.NumGoroutine()
	fmt.Printf("CPU Usage: %.2f%% (%.2f%% per core), Memory Usage: %.2f%%, Thread Count: %d, Goroutine Count: %d\n",
		cpuPercent, cp, memPercent, threadCount, gNum)
}
