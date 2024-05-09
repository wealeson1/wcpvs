package internal

import "net/http"

type TargetStruct struct {
	Request  *http.Request
	Response *http.Response
	Cache    *CacheStruct
}
