# Web Cache Poisoning Vulnerability Scanner (WCPVS)

## Overview
The Web Cache Poisoning Vulnerability Scanner (WCPVS) is a tool designed to detect web cache poisoning vulnerabilities. Web cache poisoning is an attack technique where attackers manipulate web caches to store malicious content.

## Features
- Detects if web applications are vulnerable to web cache poisoning attacks.
- Supports various web servers and caching strategies.

## Installation
1. Clone the repository to your local machine:
   ```
   git clone https://github.com/wealeson1/wcpvs.git
   ```
2. Navigate to the project directory:
   ```
   cd wcpvs/cmd
   ```
3. Build the project:
   ```
   go build wcpvs.go
   ```

## Usage
To scan using WCPVS:

Simple Scan.

```
./wcpvs -t https://www.example.com/

```
Using the Crawler.
```
./wcpvs -t https://www.example.com/ -c -hl -md 3

```

Command Line Options for WCPVS.
```
INPUT:
-l, -list string      Input file containing list of hosts to process
-rr, -request string  File containing raw request
-t, -target string[]  Input target host(s) to probe

CRAWL:
-c, -crawler            Enable crawling of the target site
-fr, -follow-redirects  Follow redirects
-hl, -headless          Enable headless mode
-sc, -system-chrome     Use system Chrome
-md, -max-depth int     Maximum depth to crawl (default 1)

HTTP OPTIONS:
-h2, -http2                   Use HTTP2 protocol
-to, -timeout int             Timeout in seconds (default 10)
-pc, -proxy-cert string       Path to proxy certificate
-purl, -proxy-url string      Proxy URL to use
-P, -post                     Use POST method
-ct, -content-type string     Content type for POST requests (default "application/json")
-qs, -query-separator string  Separator for query parameters (default "&")
-cb, -cache-buster string     Cache buster value
-dc, -decline-cookies         Decline cookies
-threads int                  Number of concurrent threads (default 10)

DIFF OPTIONS:
-cld, -cl-diff int  Content length difference
-hmd, -hm-diff int  Hash match difference

OUTPUT OPTIONS:
-ch, -cache-header string  Cache header value
-nc, -disable-color        Disable color in output
-ri, -rec-include string   Regex to include
-rl, -rec-limit int        Recursion limit

MISCELLANEOUS:
-hwp, -header-word-path string  File path of headers
-qwp, -query-word-path string   File path of query parameters
```

## Contributing
Contributions and suggestions for improvements are welcome.

## License
This project is licensed under the [Apache 2.0 License](LICENSE).