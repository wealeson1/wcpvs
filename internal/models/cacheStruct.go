package models

type CacheStruct struct {
	CBwasFound         bool
	CBisParameter      bool
	CBisHeader         bool
	CBisCookie         bool
	CBisHTTPMethod     bool
	NoCache            bool
	TimeIndicator      bool
	CBName             string
	CKIsAnyGet         bool
	CKIsHeader         bool
	CkIsCookie         bool
	CKName             string
	CKisCookie         bool
	Indicators         map[string][]string
	OrderCustomHeaders map[int]string
	HeaderCacheKeys    []string
	CookieCacheKeys    []string
	AnyGetParamsInResp bool
	InRespOfGetParams  []string
}
