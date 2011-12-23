// Copyright 2011 Phus Lu. All rights reserved.
// Use of this source code is governed by the Apache 2.0

package fetch

import (
	"fmt"
	"log"
	"bytes"
	"strings"
	"encoding/hex"
	"encoding/binary"
	"compress/zlib"

	//"appengine"
	//"appengine/urlfetch"
	
	"http"
)

const (
    Version  = "1.7.0"
    Author   = "phus.lu@gmail.com"
    Password = ""
)

func encodeData(h http.Header) []byte {
	w := bytes.NewBufferString("")
	for k, vs := range h {
		fmt.Fprintf(w, "%s=%s&", k, hex.EncodeToString([]byte(vs[0])))
	}
	return w.Bytes()
}

func decodeData(r []byte) http.Header{
    h := make(http.Header)
	for _, kv := range strings.Split(string(r), "&") {
		if kv != "" {
			pair := strings.Split(kv, "=")
			value, _ := hex.DecodeString(pair[1])
			h.Set(pair[0], string(value))
		}
	}
	return h;
}

type Webapp struct {
	response http.ResponseWriter
	request  *http.Request
}

func (app Webapp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	app.response = w
	app.request = r
	if r.Method == "POST" {
        app.post()
    } else {
        app.get()
    }
}

func (app Webapp) printResponse(status int, headers http.Header, content []byte) {
	headersBytes := encodeData(headers)

	app.response.WriteHeader(status)
	app.response.Header().Set("Content-Type", "image/gif")    
   
    if strings.HasPrefix(headers.Get("content-type"), "text/") {
    	app.response.Write([]byte("1"))
    	w, err := zlib.NewWriter(app.response)
    	defer w.Close()
    	if err != nil {
    		log.Fatalf("Error: %v", err)
    	}
    	binary.Write(w, binary.BigEndian, uint32(status))
    	binary.Write(w, binary.BigEndian, uint32(len(headersBytes)))
    	binary.Write(w, binary.BigEndian, uint32(len(content)))
    	w.Write(headersBytes)
    	w.Write(content)
    } else {
    	app.response.Write([]byte("0"))
    	binary.Write(app.response, binary.BigEndian, uint32(status))
    	binary.Write(app.response, binary.BigEndian, uint32(len(headersBytes)))
    	binary.Write(app.response, binary.BigEndian, uint32(len(content)))
    	app.response.Write(headersBytes)
    	app.response.Write(content)
    }
}

func (app Webapp) printNotify(method string, url string, status int, content []byte) {
    content = []byte("<h2>PHP Fetch Server Info</h2><hr noshade='noshade'><p>$method '$url'</p><p>Return Code: $status</p><p>Message: $content</p>")
    headers := make(http.Header)
    headers.Set("Content-Type", "text/html")
    app.printResponse(status, headers, content)
}

func (app Webapp) post() {
	app.printNotify("", "", 200, []byte("hello world"))
}

func (app Webapp) get() {
	app.response.WriteHeader(http.StatusOK)
	app.response.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(app.response, `
<html>
<head>
    <link rel="icon" type="image/vnd.microsoft.icon" href="http://www.google.cn/favicon.ico">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>GoAgent %s 已经在工作了</title>
</head>
<body>
    <table width="800" border="0" align="center">
        <tr><td align="center"><hr></td></tr>
        <tr><td align="center">
            <b><h1>GoAgent %s 已经在工作了</h1></b>
        </td></tr>
        <tr><td align="center"><hr></td></tr>

        <tr><td align="center">
            GoAgent是一个开源的HTTP Proxy软件,使用Go/Python编写,运行于Google App Engine平台上.
        </td></tr>
        <tr><td align="center"><hr></td></tr>

        <tr><td align="center">
            更多相关介绍,请参考<a href="http://code.google.com/p/goagent/">GoAgent项目主页</a>.
        </td></tr>
        <tr><td align="center"><hr></td></tr>

    </table>
</body>
</html>`, Version, Version)
}

func init() {
	http.Handle("/fetch.py", Webapp{})
}
