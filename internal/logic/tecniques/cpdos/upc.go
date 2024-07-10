package cpdos

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"strings"
)

// UPC Unkeyed Port Dos check
type UPC struct {
	CommonHttpPorts []int
}

var UPCTecnique *UPC

func NewUPC() *UPC {
	return &UPC{
		CommonHttpPorts: []int{80, 443, 8080, 8443, 8000, 81, 8008, 3000, 5000, 8888},
	}
}

func init() {
	UPCTecnique = NewUPC()
}

func (u *UPC) Scan(target *models.TargetStruct) {
	// 判断Host头是否是缓存键
	if len(target.Cache.HeaderCacheKeys) != 0 {
		for _, key := range target.Cache.HeaderCacheKeys {
			if strings.EqualFold(key, "host") {
				return
			}
		}
	}

	// 给Host头添加一个随机端口号，判断其是否为缓存键
	tmpReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		gologger.Error().Msg("UPCTecnique.Scan: " + err.Error())
		return
	}
	randomPort := utils.RandomNumber(1, 65535)
	if !strings.Contains(tmpReq.Host, ":") {
		newHostHeader := fmt.Sprintf("%s:%d", tmpReq.Host, randomPort)
		tmpReq.Host = newHostHeader
		resp, err := utils.CommonClient.Do(tmpReq)
		if err != nil {
			gologger.Error().Msg("UPCTecnique.Scan: " + err.Error())
			return
		}
		defer utils.CloseReader(resp.Body)
		if resp.StatusCode == target.Response.StatusCode {
			if utils.IsCacheHit(target, &resp.Header) {
				u.scanCommonHttpPort(target)
			}
		}
	}
}

// scanCommonHttpPort 在判断出Host不是缓存键的情况下，进行常见HTTP端口扫描，看是否会响应异常或者跳转
func (u *UPC) scanCommonHttpPort(target *models.TargetStruct) {
	if len(u.CommonHttpPorts) == 0 {
		return
	}
	for _, port := range u.CommonHttpPorts {
		// 获取一个必然可以回源的Request
		tmpReq, err := tecniques.GetSourceRequestWithCacheKey(target)
		if err != nil {
			gologger.Error().Msg("UPCTecnique.scanCommonHttpPort: " + err.Error())
			continue
		}
		if !strings.Contains(tmpReq.Host, ":") {
			tmpReq.Host = fmt.Sprintf("%s:%d", tmpReq.Host, port)
			resp, err := utils.CommonClient.Do(tmpReq)
			if err != nil {
				gologger.Error().Msg("UPCTecnique.scanCommonHttpPort: " + err.Error())
				continue
			}
			utils.CloseReader(resp.Body)
			if resp.StatusCode != target.Response.StatusCode {
				for range 3 {
					tmpReq, err := utils.CloneRequest(tmpReq)
					if err != nil {
						gologger.Error().Msg("UPCTecnique.scanCommonHttpPort: " + err.Error())
						continue
					}
					resp, err := utils.CommonClient.Do(tmpReq)
					if err != nil {
						gologger.Error().Msg("UPCTecnique.scanCommonHttpPort: " + err.Error())
						continue
					}
					utils.CloseReader(resp.Body)
					if utils.IsCacheHit(target, &resp.Header) {
						gologger.Info().Msgf("Target %s has cpdos vulnerability and tecnique is UPC %s:%d", target.Request.URL, tmpReq.Host)
						return
					}
				}
			}
		}
	}
}
