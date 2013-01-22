<?php

// Contributor:
//      Phus Lu        <phus.lu@gmail.com>

$__version__  = '2.1.11';
$__password__ = '';
$__timeout__  = 20;

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

function error_html($errno, $error, $description) {
    $error = <<<ERROR_STRING
<html><head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<title>${errno} ${error}</title>
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
<H1>${error}</H1>
${description}

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
    echo $body;
    return strlen($body);
}

function post()
{
    list($method, $url, $headers, $kwargs, $body) = @decode_request(@file_get_contents('php://input'));

    $password = $GLOBALS['__password__'];
    if ($password) {
        if (!isset($kwargs['password']) || $password != $kwargs['password']) {
            header("HTTP/1.0 403 Forbidden");
            echo '403 Forbidden';
            exit(-1);
        }
    }

    if ($body) {
        $headers['Content-Length'] = strval(strlen($body));
    }
    $headers['Connection'] = 'close';

    $timeout = $GLOBALS['__timeout__'];

    $curl_opt = array();

    $curl_opt[CURLOPT_RETURNTRANSFER] = true;
    $curl_opt[CURLOPT_BINARYTRANSFER] = true;

    $curl_opt[CURLOPT_HEADER]         = false;
    $curl_opt[CURLOPT_HEADERFUNCTION] = 'header_function';
    $curl_opt[CURLOPT_WRITEFUNCTION]  = 'write_function';


    $curl_opt[CURLOPT_FAILONERROR]    = true;
    $curl_opt[CURLOPT_FOLLOWLOCATION] = false;

    $curl_opt[CURLOPT_CONNECTTIMEOUT] = $timeout;
    $curl_opt[CURLOPT_TIMEOUT]        = $timeout;

    $curl_opt[CURLOPT_SSL_VERIFYPEER] = false;
    $curl_opt[CURLOPT_SSL_VERIFYHOST] = false;

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
            $curl_opt[CURLOPT_CUSTOMREQUEST] = $method;
            $curl_opt[CURLOPT_POSTFIELDS] = $body;
            break;
        default:
            echo 'Invalid Method: ' . var_export($method, true);
            exit(-1);
    }

    $header_array = array();
    foreach ($headers as $key => $value) {
        if ($key) {
            $header_array[] = join('-', array_map('ucfirst', explode('-', $key))).': '.$value;
        }
    }
    $curl_opt[CURLOPT_HTTPHEADER] = $header_array;

    $ch = curl_init($url);
    curl_setopt_array($ch, $curl_opt);
    $ret = curl_exec($ch);
    $errno = curl_errno($ch);
    if ($errno && !isset($GLOBALS['__status__'])) {
        echo error_html("cURL($errno)", "PHP Urlfetch Error: $method", curl_error($ch));
    }
    curl_close($ch);
}

function get() {
    header('Location: https://www.google.com/');
}

function main() {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        post();
    } else {
        get();
    }
}

main();
