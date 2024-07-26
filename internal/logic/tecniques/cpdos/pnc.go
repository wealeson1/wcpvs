package cpdos

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic"
	"github.com/wealeson1/wcpvs/internal/models"
	"github.com/wealeson1/wcpvs/pkg/utils"
	"strings"
)

type Pnc struct{}

var PncTecnique *Pnc

func NewPnc() *Pnc {
	return &Pnc{}
}

func init() {
	PncTecnique = NewPnc()
}

func (p *Pnc) Scan(target *models.TargetStruct) {
	if target.Cache.NoCache {
		return
	}
	tmpReq, err := utils.CloneRequest(target.Request)
	if err != nil {
		return
	}
	path := tmpReq.URL.Path
	if path == "" || path == "//" {
		return
	}
	// 分割路径
	pathSegments := strings.Split(path, "/")
	if len(pathSegments) > 1 {
		firstSegment := pathSegments[0]
		if firstSegment == "" {
			return
		}
		encodeChar := fmt.Sprintf("%%%02x", firstSegment[0])
		pathSegments[0] = firstSegment[1:] + encodeChar
	}
	newPath := strings.Join(pathSegments, "/")
	tmpReq.URL.Path = newPath
	resp, err := utils.CommonClient.Do(tmpReq)
	if err != nil {
		gologger.Error().Msgf("Target:%s,Pnc.scan %s", target.Request.URL, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != target.Response.StatusCode {
		tmpTarget := &models.TargetStruct{
			Request:  tmpReq,
			Response: resp,
			Cache:    &models.CacheStruct{},
		}
		err := logic.Checker.Check(target)
		if err != nil {
			gologger.Error().Msgf("Target:%s,Pnc.scan %s", target.Request.URL, err.Error())
			return
		}
		if tmpTarget.Cache.NoCache {
			return
		}
		for range 3 {
			tmpReq2, err := utils.CloneRequest(resp.Request)
			if err != nil {
				gologger.Error().Msgf("Target:%s,Pnc.scan %s", target.Request.URL, err.Error())
				continue
			}
			resp2, err := utils.CommonClient.Do(tmpReq2)
			if err != nil {
				gologger.Error().Msgf("Target:%s,Pnc.scan %s", target.Request.URL, err.Error())
				continue
			}
			if utils.IsCacheHit(target, &resp2.Header) {
				gologger.Info().Msgf("Target %s has a cpdos vulnerability,tecnique is PNC", target.Request.URL)
				return
			}
		}
	}
}
