<?php

// Note:
//     Please try to use the https url to bypass keyword filtering.
//     Otherwise, dont forgot set [paas]passowrd in proxy.ini
// Contributor:
//     Phus Lu        <phus.lu@gmail.com>

$__version__  = '2.1.13';
$__password__ = '';
$__timeout__  = 20;
$__status__ = 0;
$__xorchar__ = '';

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

function header_function($ch, $header) {
    if (substr($header, 0, 5) == 'HTTP/') {
        $terms = explode(' ', $header);
        $status = intval($terms[1]);
        $GLOBALS['__status__'] == $status;
        header('X-Status: ' . $status);
    } elseif (substr($header, 0, 17) == 'Transfer-Encoding') {
        // skip transfer-encoding
    } else {
        header($header, false, 200);
    }
    return strlen($header);
}

function write_function($ch, $body) {
    if ($GLOBALS['__xorchar__']) {
        echo $body ^ str_repeat($GLOBALS['__xorchar__'], strlen($body));
    } else {
        echo $body;
    }
    return strlen($body);
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

    if (isset($kwargs['xorchar'])) {
        $GLOBALS['__xorchar__'] = $kwargs['xorchar'];
    }

    if (isset($kwargs['hostip']) && isset($headers['Host'])) {
        $ip = $kwargs['hostip'];
        $url = preg_replace('#(.+://)([\w\.\-]+)#', '${1}'.$ip, $url);
    }

    $curl_opt = array();

    $header_array = array();
    if ($body) {
        $headers['Content-Length'] = strval(strlen($body));
    }
    $headers['Connection'] = 'close';
    foreach ($headers as $key => $value) {
        if ($key) {
            $header_array[] = join('-', array_map('ucfirst', explode('-', $key))).': '.$value;
        }
    }

    $curl_opt[CURLOPT_HTTPHEADER] = $header_array;

    $curl_opt[CURLOPT_RETURNTRANSFER] = true;
    $curl_opt[CURLOPT_BINARYTRANSFER] = true;

    $curl_opt[CURLOPT_HEADER]         = false;
    $curl_opt[CURLOPT_HEADERFUNCTION] = 'header_function';
    $curl_opt[CURLOPT_WRITEFUNCTION]  = 'write_function';


    $curl_opt[CURLOPT_FAILONERROR]    = false;
    $curl_opt[CURLOPT_FOLLOWLOCATION] = false;

    $curl_opt[CURLOPT_CONNECTTIMEOUT] = $GLOBALS['__timeout__'];
    $curl_opt[CURLOPT_TIMEOUT]        = $GLOBALS['__timeout__'];

    if (isset($kwargs['validate']) && @strval($kwargs['validate'])) {
        $curl_opt[CURLOPT_SSL_VERIFYPEER] = true;
        $curl_opt[CURLOPT_SSL_VERIFYHOST] = true;
    } else {
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
            $curl_opt[CURLOPT_POSTFIELDS] = $body;
            break;
        case 'PUT':
        case 'DELETE':
        case 'OPTIONS':
        case 'TRACE':
            $curl_opt[CURLOPT_CUSTOMREQUEST] = $method;
            $curl_opt[CURLOPT_POSTFIELDS] = $body;
            break;
        default:
            echo message_html("403 Forbidden", "Invalid Method: $method", "$method '$url'");
            exit(-1);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, $curl_opt);
    curl_exec($ch);
    $errno = curl_errno($ch);
    if ($errno && !$GLOBALS['__status__']) {
        header('HTTP/1.1 502 Bad Gateway');
        echo message_html("500 Internal Server Error", "PHP Urlfetch Error: $method", "cURL($errno): ".curl_error($ch));
    }
    curl_close($ch);
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
