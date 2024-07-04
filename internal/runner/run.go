package logic

import (
	"github.com/projectdiscovery/gologger"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques"
	"github.com/wealeson1/wcpvs/internal/logic/tecniques/cpdos"
	"github.com/wealeson1/wcpvs/internal/models"
	"sync"
)

func Run(target *models.TargetStruct) {
	err := Checker.Check(target)
	if err != nil {
		return
	}
	if target.Cache.NoCache {
		gologger.Info().Msgf("The target %s has no caching mechanism.", target.Request.URL)
		return
	}
	gologger.Info().Msgf("The target %s has a caching mechanism; start identifying cache keys.", target.Request.URL)
	err = CacheKeysFinder.Check(target)
	if err != nil {
		return
	}
	if target.Cache.NoCache {
		gologger.Info().Msgf("The target %s does not have any cache keys.", target.Request.URL)
		return
	}
	scans := []Scan{cpdos.HHOTecnique,
		cpdos.HMCTecniques,
		cpdos.HMOTecniques,
		tecniques.HCPTechniques,
		tecniques.ParameterCP,
		tecniques.CCPTechniques,
		cpdos.RDDTecniques,
	}
	var wg sync.WaitGroup
	for _, scan := range scans {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scan.Scan(target)
		}()
	}
	wg.Wait()
	wg.Add(1)
	go func() {
		defer wg.Done()
		tecniques.FatGetTechniques.Scan(target)

	}()
	wg.Wait()
}

type Scan interface {
	Scan(target *models.TargetStruct)
}
