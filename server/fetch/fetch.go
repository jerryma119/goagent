// Copyright 2011 Phus Lu. All rights reserved.
// Use of this source code is governed by the Apache 2.0

package fetch

import (
	"fmt"
	"bytes"
	"strings"
	"strconv"
	"encoding/hex"
	"encoding/binary"
	//"compress/zlib"
	
	"http"
	//"io"
	//"strconv"

	//"appengine"
	//"appengine/urlfetch"
)

const (
    Version  = "1.7.0"
    Author   = "phus.lu@gmail.com"
    Password = ""
)

func encodeData(h http.Header) string {
	w := bytes.NewBufferString("")
	for k, vs := range h {
		fmt.Fprintf(w, "%s=%s&", k, hex.Dump([]byte(strings.Join(vs, " "))))
	}
	return w.String()
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

func printResponse(status int, headers http.Header, content string, w http.ResponseWriter) {
	data := bytes.NewBufferString("")
    strheaders := encodeData(headers)
    //contentType := headers.Get("content-type")
    //if strings.HasPrefix(contentType, "text/") {
    //	data.WriteString("1")
    //	data.WriteString("gzcompress(pack('NNN', $status, strlen($strheaders), strlen($content)) . $strheaders . $content")
   // } else {
    	data.WriteString("0")
    	binary.Write(data, binary.BigEndian, status)
    	binary.Write(data, binary.BigEndian, len(strheaders))
    	binary.Write(data, binary.BigEndian, len(content))
    	data.WriteString(strheaders)
    	data.WriteString(content)
   // }
    w.WriteHeader(status)
    w.Header().Set("Content-Type", "image/gif")
    databytes := data.Bytes()
    w.Header().Set("Content-Length", strconv.Itoa(len(databytes)))
    w.Write(databytes)
}

func printNotify(method string, url string, status int, content string, w http.ResponseWriter) {
    content = "<h2>PHP Fetch Server Info</h2><hr noshade='noshade'><p>$method '$url'</p><p>Return Code: $status</p><p>Message: $content</p>"
    headers := make(http.Header)
    headers.Set("content-type", "text/html")
    printResponse(status, headers, content, w)
}

func post(w http.ResponseWriter, r *http.Request) {
	printNotify("", "", 200, "hello world", w);
}

func get(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
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

func handle(w http.ResponseWriter, r *http.Request) {
    if r.Method == "POST" {
        post(w, r);
    } else {
        get(w, r);
    }
}

func init() {
	http.HandleFunc("/fetch.py", handle)
}
 