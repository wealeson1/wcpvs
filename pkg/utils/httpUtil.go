package utils

import (
	"bytes"
	"github.com/projectdiscovery/gologger"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type MyClient struct {
	*http.Client
}

var CommonClient = MyClient{http.DefaultClient}

func (c *MyClient) Do(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := 0; i < 3; i++ {
		resp, err = c.Client.Do(req)
		if err == nil {
			return resp, nil
		}
		// Optional: add a delay between retries
		time.Sleep(time.Second * time.Duration(i+1))
		//fmt.Printf("Retrying request... Attempt #%d\n", i+2)
	}

	return resp, err
}

func init() {
}

// CloneRequest 克隆一个 *http.Request 对象，包括其方法、URL、头字段和正文。
func CloneRequest(r *http.Request) (*http.Request, error) {
	// 复制 URL
	u := *r.URL
	// 创建一个新的请求对象
	req := &http.Request{
		Method:        r.Method,
		URL:           &u,
		Header:        make(http.Header, len(r.Header)),
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Close:         r.Close,
		Host:          r.Host,
		MultipartForm: r.MultipartForm,
		RemoteAddr:    r.RemoteAddr,
		TLS:           r.TLS,
		RequestURI:    r.RequestURI,
		ContentLength: r.ContentLength,
		Form:          make(url.Values), // 创建一个新的 URL.Values 对象
		PostForm:      make(url.Values), // 创建一个新的 URL.Values 对象

	}

	// 复制头字段
	for k, v := range r.Header {
		req.Header[k] = v
	}
	// 复制 Trailer字段
	if req.Trailer != nil {
		req.Trailer = make(http.Header, len(r.Trailer))
		for k, v := range r.Trailer {
			req.Trailer[k] = v
		}
	}

	// 复制请求正文，如果原始请求有正文的话
	if r.Body != nil {
		// 读取原始请求的正文内容
		var err error
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		// 使用相同的正文内容创建一个新的 io.ReadCloser
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		// 添加了 GetBody 方法，这样克隆的请求就可以返回一个可以重复读取的正文。
		req.GetBody = func() (io.ReadCloser, error) {
			return req.Body, nil
		}
		req.ContentLength = int64(len(bodyBytes))
	}
	return req, nil
}

// AddParam 根据不同的请求方法添加参数，目前先不考虑其他类型的参数，JSON或者XML。
func AddParam(req *http.Request, method, paramName, paramValue string) *http.Request {
	if method == "GET" {
		// Parse the URL and add the query parameter
		u := req.URL
		q := u.Query()
		q.Del(paramName)
		q.Add(paramName, paramValue)
		u.RawQuery = q.Encode()
		req.URL = u
	} else if method == "POST" {
		// Ensure the content type is application/x-www-form-urlencoded
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		// Parse the existing form values
		err := req.ParseForm()
		if err != nil {
			gologger.Error().Msg(err.Error())
			return nil
		}
		req.Form.Add(paramName, paramValue)

		// Re-encode form values and update the request body
		req.Body = io.NopCloser(strings.NewReader(req.Form.Encode()))
		req.ContentLength = int64(len(req.Form.Encode()))
	}
	return req
}
