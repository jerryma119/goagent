<?php

// Note:
//     Please try to use the https url to bypass keyword filtering.
//     Otherwise, dont forgot set [paas]passowrd in proxy.ini
// Contributor:
//     Phus Lu        <phus.lu@gmail.com>

$__version__  = '3.0.5';
$__password__ = '';
$__timeout__  = 20;
$__content_type__ = 'image/gif';

class URLFetch {
    protected $body_maxsize = 4194304;
    protected $headers = array();
    protected $body = '';
    protected $body_size = 0;

    function __construct() {
    }

    function urlfetch_readheader($ch, $header) {
        $kv = array_map('trim', explode(':', $header, 2));
        if (isset($kv[1])) {
            $key = join('-', array_map('ucfirst', explode('-', $kv[0])));
            $value = $kv[1];
            if ($key == 'Set-Cookie') {
                if (!array_key_exists('Set-Cookie', $this->headers)) {
                    $this->headers['Set-Cookie'] = $value;
                } else {
                    $this->headers['Set-Cookie'] .= "\r\nSet-Cookie: " . $value;
                }
            } else {
                $this->headers[$key] = $kv[1];
            }
        }
        return strlen($header);
    }

    function urlfetch_readbody($ch, $data) {
        $bytes = strlen($data);
        if ($this->body_size + $bytes > $this->body_maxsize) {
            return -1;
        }
        $this->body_size += $bytes;
        $this->body .= $data;
        return $bytes;
    }

    function urlfetch($url, $payload, $method, $headers, $follow_redirects, $deadline, $validate_certificate) {

        $this->headers = array();
        $this->body = '';
        $this->body_size = 0;

        if ($payload) {
            $headers['Content-Length'] = strval(strlen($payload));
        }
        $headers['Connection'] = 'close';

        $curl_opt = array();

        $curl_opt[CURLOPT_TIMEOUT]        = $deadline;
        $curl_opt[CURLOPT_CONNECTTIMEOUT] = $deadline;
        $curl_opt[CURLOPT_RETURNTRANSFER] = true;
        $curl_opt[CURLOPT_BINARYTRANSFER] = true;
        $curl_opt[CURLOPT_FAILONERROR]    = true;

        if (!$follow_redirects) {
            $curl_opt[CURLOPT_FOLLOWLOCATION] = false;
        }

        if ($deadline) {
            $curl_opt[CURLOPT_CONNECTTIMEOUT] = $deadline;
            $curl_opt[CURLOPT_TIMEOUT] = $deadline;
        }

        if (!$validate_certificate) {
            $curl_opt[CURLOPT_SSL_VERIFYPEER] = false;
            $curl_opt[CURLOPT_SSL_VERIFYHOST] = false;
        }

        switch (strtoupper($method)) {
            case 'HEAD':
                $curl_opt[CURLOPT_NOBODY] = true;
                break;
            case 'GET':
                break;
            case 'POST':
                $curl_opt[CURLOPT_POST] = true;
                $curl_opt[CURLOPT_POSTFIELDS] = $payload;
                break;
            case 'PUT':
            case 'DELETE':
                $curl_opt[CURLOPT_CUSTOMREQUEST] = $method;
                $curl_opt[CURLOPT_POSTFIELDS] = $payload;
                break;
            default:
                print(message_html('502 Urlfetch Error', 'Invalid Method: ' . $method,  $url));
                exit(-1);
        }

        $header_array = array();
        foreach ($headers as $key => $value) {
            if ($key) {
                $header_array[] = join('-', array_map('ucfirst', explode('-', $key))).': '.$value;
            }
        }
        $curl_opt[CURLOPT_HTTPHEADER] = $header_array;

        $curl_opt[CURLOPT_HEADER]         = false;
        $curl_opt[CURLOPT_HEADERFUNCTION] = array(&$this, 'urlfetch_readheader');
        $curl_opt[CURLOPT_WRITEFUNCTION]  = array(&$this, 'urlfetch_readbody');

        $ch = curl_init($url);
        curl_setopt_array($ch, $curl_opt);
        $ret = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno = curl_errno($ch);
        if ($errno)
        {
            $error =  $errno . ': ' .curl_error($ch);
        } else {
            $error = '';
        }
        curl_close($ch);

        $this->headers['Connection'] = 'close';
        $content_length = isset($this->headers['Content-Length']) ? 1*$this->headers['Content-Length'] : 0;

        if ($status < 200 && $errno == 23 && $content_length && $this->body_size < $content_length) {
            $status = 206;
            $range_end = $this->body_size - 1;
            $this->headers['Content-Range'] = "bytes 0-$range_end/$content_length";
            $this->headers['Accept-Ranges'] = 'bytes';
            $this->headers['Content-Length'] = $this->body_size;
        }

        $response = array('status' => $status, 'headers' => $this->headers, 'content' => $this->body, 'error' => $error);
        return $response;
    }
}


function message_html($title, $banner, $detail) {
    $error = <<<ERROR_STRING
<html><head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<title>${title}</title>
<style><!--
body {font-family: arial,sans-serif}
div.nav {margin-top: 1ex}
div.nav A {font-size: 10pt; font-family: arial,sans-serif}
span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
div.nav A,span.big {font-size: 12pt; color: #0000cc}
div.nav A {font-size: 10pt; color: black}
A.l:link {color: #6f6f6f}
A.u:link {color: green}
//--></style>

</head>
<body text=#000000 bgcolor=#ffffff>
<table border=0 cellpadding=2 cellspacing=0 width=100%>
<tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Error</b></td></tr>
<tr><td>&nbsp;</td></tr></table>
<blockquote>
<H1>${banner}</H1>
${detail}

<p>
</blockquote>
<table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
</body></html>
ERROR_STRING;
    return $error;
}


function decode_request($data) {
    list($headers_length) = array_values(unpack('n', substr($data, 0, 2)));
    $headers_data = gzinflate(substr($data, 2, $headers_length));
    $body = substr($data, 2+intval($headers_length));

    $method  = '';
    $url     = '';
    $headers = array();
    $kwargs  = array();

    foreach (explode("\n", $headers_data) as $kv) {
        $pair = explode(':', $kv, 2);
        $key  = $pair[0];
        $value = trim($pair[1]);
        if ($key == 'G-Method') {
            $method = $value;
        } else if ($key == 'G-Url') {
            $url = $value;
        } else if (substr($key, 0, 2) == 'G-') {
            $kwargs[strtolower(substr($key, 2))] = $value;
        } else if ($key) {
            $key = join('-', array_map('ucfirst', explode('-', $key)));
            $headers[$key] = $value;
        }
    }
    if (isset($headers['Content-Encoding'])) {
        if ($headers['Content-Encoding'] == 'deflate') {
            $body = gzinflate($body);
            $headers['Content-Length'] = strval(strlen($body));
            unset($headers['Content-Encoding']);
        }
    }
    return array($method, $url, $headers, $kwargs, $body);
}

function print_response($status, $headers, $content, $support_gzip=true) {
    $headers['Content-Length'] = strval(strlen($content));
    $strheaders = '';
    foreach ($headers as $key => $value) {
        $strheaders .= $key. ':' . $value . "\n";
    }
    $content_type = isset($headers['Content-Type']) ? $headers['Content-Type'] : '';
    if ($support_gzip && !isset($headers['Content-Encoding']) && $content_type && (substr($content_type, 0, 5) == 'text/' || substr($content_type, 0, 16) == 'application/json' || substr($content_type, 0, 22) == 'application/javascript')) {
        $strheaders .= 'Content-Encoding:gzip';
        $content = gzcompress($content);
    }
    $response_headers_data = gzdeflate(rtrim($strheaders));
    header('Content-Type: ' . $GLOBALS['__content_type__']);
    print(pack('nn', $status, strlen($response_headers_data)) . $response_headers_data);
    print($content);
}


function post()
{
    list($method, $url, $headers, $kwargs, $body) = @decode_request(@file_get_contents('php://input'));

    if ($GLOBALS['__password__']) {
        if (!isset($kwargs['password']) || $GLOBALS['__password__'] != $kwargs['password']) {
            header("HTTP/1.0 403 Forbidden");
            echo '403 Forbidden';
            exit(-1);
        }
    }

    if (isset($kwargs['hostip']) && isset($headers['Host'])) {
        $ip = $kwargs['hostip'];
        $url = preg_replace('#(.+://)([\w\.\-]+)#', '${1}'.$ip, $url);
    }

    $headers['Connection'] = 'close';

    $urlfetch = new URLFetch();
    $response = $urlfetch->urlfetch($url, $body, $method, $headers, False, $deadline, False);
    $status = $response['status'];
    if (200 <= $status && $status < 400) {
        print_response($status, $response['headers'], $response['content'], isset($headers['Accept-Encoding']) && strpos($headers['Accept-Encoding'], 'gzip'));
    } else {
        header('HTTP/1.0 502');
        echo message_html('502 Urlfetch Error', 'PHP Curl Urlfetch Error: ' . $status,  $response['error']);
    }
}

function get() {
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $_SERVER['SERVER_NAME'];
    $domain = preg_replace('/.*\\.(.+\\..+)$/', '$1', $host);
    if ($host && $host != $domain && $host != 'www'.$domain) {
        header('Location: http://www.' . $domain);
    } else {
        header('Location: https://www.google.com');
    }
}

function main() {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        post();
    } else {
        get();
    }
}

main();
