package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
)

// 扫描器黑名单UA投毒

type Blcp struct {
	ScannerBlackList []string
}

var BlcpTecnique *Blcp

func init() {
	BlcpTecnique = &Blcp{
		ScannerBlackList: []string{
			"Fuzz Faster U Fool", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "sqlmap/1.3.11#stable (http://sqlmap.org)", "gobuster/3.1.0", "Wfuzz/2.2", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "masscan/1.3", "blekkobot",
		},
	}
}

func (b *Blcp) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}
	for _, v := range b.ScannerBlackList {
		tmpReq, err := tecniques.GetSourceRequestWithCacheKey(target)
		if err != nil {
			return
		}
		tmpReq.Header.Set("User-Agent", v)
		tmpResp, err := utils.CommonClient.Do(tmpReq)
		if err != nil {
			return
		}
		if tmpResp.StatusCode != target.Response.StatusCode {
			//tmpTarget := &models.TargetStruct{
			//	Response: tmpResp,
			//	Cache:    &models.CacheStruct{},
			//}
			//hasCache, _ := logic.Checker.IsCacheAvailable(tmpTarget)
			hasCustomHeaders, _ := utils.HasCustomHeaders(tmpResp)
			if !hasCustomHeaders {
				return
			}
			for range 3 {
				tmpReq2, err := utils.CloneRequest(tmpResp.Request)
				if err != nil {
					continue
				}
				tmpResp2, err := utils.CommonClient.Do(tmpReq2)
				if err != nil {
					continue
				}
				if utils.IsCacheHit(target, &tmpResp2.Header) && target.Response.StatusCode != tmpResp2.StatusCode {
					gologger.Info().Msgf("Target %s has a CPDOS vulnerability, detected using a request with a blacklisted security scanner's User-Agent: %s", target.Request.URL, v)
					return
				}
			}
		}
	}
}
