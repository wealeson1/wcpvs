package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/internal/runner"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"io"
	"net/http"
	"net/url"
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
	var targetsChannel = make(chan *models.TargetStruct, 1000)
	var rawUrlChannel = make(chan string, 1000)

	// 启动资源监控goroutine
	go func() {
		for {
			Monitor(os.Getpid(), &targetsChannel, &rawUrlChannel)
			time.Sleep(1 * time.Second) // 每隔10秒打印一次监控信息
		}
	}()

	// 启动工作goroutine
	for range threadCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				target, ok := <-targetsChannel
				if !ok {
					return
				}
				runner.Run(target)
			}
		}()
	}

	// 强制转换为单向channel
	rawUrlChannelReadOnly := (<-chan string)(rawUrlChannel)
	TargetsChannelWriteOnly := (chan<- *models.TargetStruct)(targetsChannel)

	// 开启中介者模式
	wg.Add(1)
	go func() {
		defer wg.Done()
		Mediator(&rawUrlChannelReadOnly, 1000, &TargetsChannelWriteOnly)
	}()

	// 如果未开启爬虫模式
	if !runner.ScanOptions.Crawler {
		for _, rawUrl := range runner.ScanOptions.Urls {
			rawUrlChannel <- rawUrl
		}
		close(rawUrlChannel)
	}
	// 等待所有线程结束
	wg.Wait()
	gologger.Info().Msgf("扫描结束")

}

// Monitor debug 模式，监控程序使用的资源状况
// @param pid 进程PID
func Monitor[T any](pid int, targetsChannel *chan T, rawUrlChannel *chan string) {
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
	threadCount := pprof.Lookup("threadCreate").Count()
	gNum := runtime.NumGoroutine()
	gologger.Info().Msgf("CPU Usage: %.2f%% (%.2f%% per core), Memory Usage: %.2f%%, Thread Count: %d, Goroutine Count: %d\n",
		cpuPercent, cp, memPercent, threadCount, gNum)

	gologger.Info().Msgf("rawUrlChannel Length:[%d];TargetsChannel Length:[%d]\n", len(*rawUrlChannel), len(*targetsChannel))
}

// Mediator 充当中介者模式
// @description：处理生产者提供的URL，供给消费者需要的target对象
// @param urlsChan: 与生产者共有的chan，接收生产生产的URL
// @param targetChan: 与消费者共有的chan，传送给消费者待消费的Target
// @param maxThread: 最大处理线程数
// @return nil
func Mediator(urlsChan *<-chan string, maxThread int, targetChan *chan<- *models.TargetStruct) {
	var wg sync.WaitGroup
	// maxThread 默认为10
	if maxThread < 1 {
		maxThread = 10
	}
	// 开启 maxThread 个线程处理URL
	for range maxThread {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				rawUrl, ok := <-*urlsChan
				// 如果上游chan通知已经关闭，并且遗留数据已经被处理完毕，关闭所有线程
				if !ok {
					return
				}
				isAlive, err, target := IsAlive(rawUrl)
				if err == nil && isAlive == true {
					*targetChan <- target
				}
			}
		}()
	}
	wg.Wait()
	//通知下游已经没有Target会被生产出来了
	close(*targetChan)
	//for {
	//	rawUrl, ok := <-*urlsChan
	//	if !ok {
	//		break
	//	}
	//	wg.Add(1)
	//	go func() {
	//		defer wg.Done()
	//		isAlive, err, target := IsAlive(rawUrl)
	//		if err == nil && isAlive == true {
	//			*targetChan <- target
	//		}
	//	}()
	//}
	//wg.Wait()
	//// 通知下游已经没有Target会被生产出来了
	//close(*targetChan)
}

// IsAlive rawURL 存活检查
// @param rawUrl URL 字符串
// @return bool 是否存活
// @return error 错误信息
// @return *models.TargetStruct 实例
func IsAlive(rawUrl string) (bool, error, *models.TargetStruct) {
	// 重试3次
	_, err := url.Parse(rawUrl)
	if err != nil {
		return false, err, nil
	}
	for range 3 {
		req, err := http.NewRequest("GET", rawUrl, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0")
		resp, err := utils.CommonClient.Do(req)
		if err != nil {
			gologger.Error().Msgf("%s [%s]", rawUrl, err.Error())
			continue
		}
		if resp.StatusCode >= 500 {
			gologger.Error().Msgf("%s [%d]", rawUrl, resp.StatusCode)
			utils.CloseReader(resp.Body)
			continue
		}
		byteRespBody, err := io.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msgf("%s [%s]", rawUrl, err.Error())
			utils.CloseReader(resp.Body)
			continue
		}
		utils.CloseReader(resp.Body)
		target := &models.TargetStruct{
			Request:  resp.Request,
			Response: resp,
			RespBody: byteRespBody,
			Cache:    &models.CacheStruct{},
		}
		return true, nil, target
	}
	return false, nil, nil
}
