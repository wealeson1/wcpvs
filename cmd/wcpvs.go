package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/internal/runner"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"net/http"
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
			time.Sleep(1 * time.Second) // 每隔10秒打印一次监控信息
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

	// 存活检查
	aliveTargets := AliveCheck(runner.ScanOptions.Urls, 1000)
	gologger.Info().Msgf("目标存活数量：%d", len(aliveTargets))
	if !runner.ScanOptions.Crawler && len(aliveTargets) > 0 {
		for _, target := range aliveTargets {
			TargetsChannel <- target
		}
	} else {
		for _, target := range aliveTargets {
			runner.Crawl(target.Request.URL.String(), TargetsChannel)
		}
	}
	// 通知所有goroutine任务已完成
	close(TargetsChannel)
	wg.Wait()
	gologger.Info().Msgf("扫描结束")
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

func AliveCheck(urls []string, maxGoroutines int) []*models.TargetStruct {
	var wg sync.WaitGroup
	aliveUrlTargets := make([]*models.TargetStruct, 0)
	urlChan := make(chan string, maxGoroutines)

	for i := 0; i < maxGoroutines; i++ {
		go func() {
			for url := range urlChan {
				var resp *http.Response
				var err error
				// 3 time for retry
				for range 3 {
					resp, err = utils.CommonClient.Get(url)
					if err != nil {
						continue
					}
					break
				}
				if err != nil {
					gologger.Error().Msgf("%s [Error]", url)
					wg.Done()
					continue
				}
				utils.CloseReader(resp.Body)
				if resp.StatusCode >= 500 {
					gologger.Error().Msgf("%s [%s]", url, resp.Status)
					wg.Done()
					continue
				}
				gologger.Info().Msgf("%s [%s]", url, resp.Status)
				primitiveResp, err := utils.CommonClient.Get(url)
				if err != nil || primitiveResp == nil {
					wg.Done()
					continue
				}
				respBody, err := io.ReadAll(primitiveResp.Body)
				if err != nil {
					gologger.Error().Msg("wcpvs.main:" + err.Error())
					wg.Done()
					continue
				}
				utils.CloseReader(primitiveResp.Body)
				target := &models.TargetStruct{
					Request:  primitiveResp.Request,
					Response: primitiveResp,
					RespBody: respBody,
					Cache:    &models.CacheStruct{},
				}
				aliveUrlTargets = append(aliveUrlTargets, target)
				wg.Done()
			}
		}()
	}

	for _, url := range urls {
		wg.Add(1)
		urlChan <- url
	}

	close(urlChan)
	wg.Wait()
	return aliveUrlTargets
}
