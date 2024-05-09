package internal

type CacheStruct struct {
	CBwasFound     bool
	CBisParameter  bool
	CBisHeader     bool
	CBisCookie     bool
	CBisHTTPMethod bool
	NoCache        bool
	TimeIndicator  bool
	Indicator      []string
	CBName         string
}
