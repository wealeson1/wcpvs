package models

import (
	"net/http"
)

type TargetStruct struct {
	Request  *http.Request
	Response *http.Response
	RespBody []byte
	ReqBody  []byte
	Cache    *CacheStruct
}
