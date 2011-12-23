// Copyright 2011 Phus Lu. All rights reserved.
// Use of this source code is governed by the Apache 2.0

package fetch

import (
	"fmt"
	"log"
	"bytes"
	"strings"
	//"strconv"
	"encoding/hex"
	"encoding/binary"
	"compress/zlib"
	"io/ioutil"

	"appengine"
	"appengine/urlfetch"
	"http"
)

const (
    Version  = "1.7.0"
    Author   = "phus.lu@gmail.com"
    Password = ""
    
    FetchMax     = 3
    FetchMaxSize = 1024*1024
    Deadline     = 30
)

func encodeData(dic map[string]string) []byte {
	w := bytes.NewBufferString("")
	for k, v := range dic {
		fmt.Fprintf(w, "%s=%s&", k, hex.EncodeToString([]byte(v)))
	}
	return w.Bytes()
}

func decodeData(qs []byte) map[string]string {
    m := make(map[string]string)
	for _, kv := range strings.Split(string(qs), "&") {
		if kv != "" {
			pair := strings.Split(kv, "=")
			value, _ := hex.DecodeString(pair[1])
			m[pair[0]] = string(value)
		}
	}
	return m;
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

func (app Webapp) printResponse(status int, header map[string]string, content []byte) {
	headerBytes := encodeData(header)

	app.response.WriteHeader(status)
	app.response.Header().Set("Content-Type", "image/gif")    
   
    if contentType, ok := header["content-type"]; ok && strings.HasPrefix(contentType, "text/") {
    	app.response.Write([]byte("1"))
    	w, err := zlib.NewWriter(app.response)	
    	if err != nil {
    		log.Fatalf("zlib.NewWriter(app.response) Error: %v", err)
    	}
    	defer w.Close()
    	binary.Write(w, binary.BigEndian, uint32(status))
    	binary.Write(w, binary.BigEndian, uint32(len(headerBytes)))
    	binary.Write(w, binary.BigEndian, uint32(len(content)))
    	w.Write(headerBytes)
    	w.Write(content)
    } else {
    	app.response.Write([]byte("0"))
    	binary.Write(app.response, binary.BigEndian, uint32(status))
    	binary.Write(app.response, binary.BigEndian, uint32(len(headerBytes)))
    	binary.Write(app.response, binary.BigEndian, uint32(len(content)))
    	app.response.Write(headerBytes)
    	app.response.Write(content)
    }
}

func (app Webapp) printNotify(method string, url string, status int, text string) {
    content := []byte(fmt.Sprintf("<h2>PHP Fetch Server Info</h2><hr noshade='noshade'><p>%s '%s'</p><p>Return Code: %d</p><p>Message: %s</p>", method, url, status, text))
    headers := map[string]string {"Content-Type": "text/html"}
    app.printResponse(status, headers, content)
}

func (app Webapp) post() {
	r, err := zlib.NewReader(app.request.Body)
	if err != nil {
		log.Fatalf("zlib.NewReader(app.request.Body) Error: %v", err)
    }
    defer r.Close()
    data, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatalf("io.ReadFull(r) Error: %v", err)
    }    
    request := decodeData(data)
     
    method  := request["method"]
    url     := request["url"]
    headers := request["headers"]
    
    if Password != "" {
    	password, ok := request["password"]
    	if !ok || password != Password {
    		app.printNotify(method, url, 403, "Wrong Password.")
    	}
    }
    
    if !strings.HasPrefix(url, "http") {
    	app.printNotify(method, url, 501, "Unsupported Scheme")
    }
    
    payload := strings.NewReader(request["payload"])
    req, err := http.NewRequest(method, url, payload)
    if err != nil {
    	app.printNotify(method, url, 500, "http.NewRequest(method, url, payload) failed")
    }
    
    for _, line := range strings.Split(headers, "\r\n") {
    	kv := strings.SplitN(line, ":", 2)
    	if len(kv) == 2 {
    		req.Header.Set(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
    	}
    }
    
    var errors []string
    for i := 0; i < FetchMax; i++ {
    	t := &urlfetch.Transport{Context:appengine.NewContext(app.request), DeadlineSeconds:float64(Deadline)}
    	resp, err := t.RoundTrip(req)
    	if err == nil {
        	//app.printResponse(resp.StatusCode, resp.Header, ioutil.ReadAll(resp.Body));
        	app.printNotify(method, url, 200, fmt.Sprintf("resp.StatusCode=%v resp.Header=%v resp.ContentLength=%v", resp.StatusCode, resp.Header, resp.ContentLength))
        	return
    	} else {
    		errors = append(errors, err.String())
    	}
    }
	app.printNotify(method, url, 502, fmt.Sprintf("Fetch Server Failed: %v", errors))
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
