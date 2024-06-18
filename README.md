```markdown
# Web Cache Poisoning Vulnerability Scanner (WCPVS)

## Overview
Web Cache Poisoning Vulnerability Scanner (WCPVS) 是一个用于检测Web缓存投毒漏洞的工具。Web缓存投毒是一种攻击技术，攻击者利用它来操纵Web缓存，导致缓存中存储恶意内容。

## Features
- 检测Web应用是否容易受到Web缓存投毒攻击。
- 支持多种Web服务器和缓存策略。

## Installation
1. 克隆仓库到本地机器
   ```
git clone https://github.com/wealeson1/wcpvs.git
   ```
2. 进入项目目录
   ```
cd wcpvs/cmd
   ```
3. 安装编译
   ```
go build wcpvs.go
   ```

## Usage
如何使用WCPVS进行扫描：

```
./wcpvs -t https://www.example.com/ 


INPUT:
-l, -list string      input file containing list of hosts to process
-rr, -request string  file containing raw request
-t, -target string[]  input target host(s) to probe

CRAWL:
-c, -crawler            enable crawling of the target site
-fr, -follow-redirects  follow redirects
-hl, -headless          enable headless mode
-sc, -system-chrome     use system chrome
-md, -max-depth int     Maximum depth to crawl (default 1)

HTTP OPTIONS:
-h2, -http2                   use HTTP2 protocol
-to, -timeout int             timeout in seconds (default 10)
-pc, -proxy-cert string       path to proxy certificate
-purl, -proxy-url string      proxy URL to use
-P, -post                     use POST method
-ct, -content-type string     content type for POST requests (default "application/json")
-qs, -query-separator string  separator for query parameters (default "&")
-cb, -cache-buster string     cache buster value
-dc, -decline-cookies         decline cookies
-threads int                  number of concurrent threads (default 10)

DIFF OPTIONS:
-cld, -cl-diff int  content length difference
-hmd, -hm-diff int  hash match difference

OUTPUT OPTIONS:
-ch, -cache-header string  cache header value
-nc, -disable-color        disable color in output
-ri, -rec-include string   regex to include
-rl, -rec-limit int        recursion limit

MISCELLANEOUS:
-hwp, -header-word-path string  file path of headers
-qwp, -query-word-path string   file path of query parameters

```
## Contributing
欢迎贡献代码或提出改进建议。

## License
该项目采用 [apache2 License](LICENSE)。
```

