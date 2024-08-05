package cpdos

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"net/http"
	"strings"
)

type Hhcn struct {
}

var HhcnTecnique *Hhcn

func NewHhcn() *Hhcn {
	return &Hhcn{}
}

func init() {
	HhcnTecnique = NewHhcn()
}

func (h *Hhcn) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}
	tmpReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		gologger.Error().Msgf("Target:%s Hhcn.scan failed, %v", target.Request.URL, err)
		return
	}
	if tmpReq.Host == "" {
		gologger.Error().Msgf("Target:%s Hhcn.scan failed, no host", target.Request.URL)
		return
	}
	tmpReq.Host = strings.ToUpper(tmpReq.Host)
	resp, err := http.DefaultClient.Do(tmpReq)
	if err != nil {
		gologger.Error().Msgf("Target:%s Hhcn.scan failed, %v", target.Request.URL, err)
		return
	}
	defer resp.Body.Close()
	if utils.IsCacheMiss(target, &resp.Header) {
		return
	}

	tmpReq2, err := tecniques.GetSourceRequestWithCacheKey(target)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	tmpReq2.Host = strings.ToUpper(tmpReq2.Host)
	resp2, err := http.DefaultClient.Do(tmpReq2)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != target.Response.StatusCode {
		for range 3 {
			tmpReq3, err := tecniques.GetSourceRequestWithCacheKey(target)
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}
			tmpReq3.Host = strings.ToUpper(tmpReq3.Host)
			resp3, err := http.DefaultClient.Do(tmpReq3)
			if err != nil {
				continue
			}
			if utils.IsCacheHit(target, &resp3.Header) && target.Response.StatusCode != resp3.StatusCode {
				gologger.Info().Msgf("Target %s has a cache-poisoning vulnerability by Host header case normalization", target.Request.URL)
				return
			}
		}
	}
}
