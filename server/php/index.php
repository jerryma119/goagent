<?php

// Contributor:
//      Phus Lu        <phus.lu@gmail.com>

$__version__  = '2.0.1';
$__password__ = '';
$__timeout__  = 20;

function encode_request($headers, $kwargs) {
    $data = '';
    foreach ($headers as $key => $value) {
        $data .= "$key: $value\r\n";
    }
    foreach ($kwargs as $key => $value) {
        $data .= "X-Goa-$key: $value\r\n";
    }
    return base64_encode(gzcompress($data));
}

function decode_request($request) {
    $data    = gzuncompress(base64_decode($request));
    $headers = array();
    $kwargs  = array();
    foreach (explode("\r\n", $data) as $kv) {
        $pair = explode(':', $kv, 2);
        $key  = $pair[0];
        $value = trim($pair[1]);
        if (substr($key, 0, 6) == 'X-Goa-') {
            $kwargs[strtolower(substr($key, 6))] = $value;
        } else if ($key) {
            $headers[$key] = $value;
        }
    }
    return array($headers, $kwargs);
}

function header_function($ch, $header){
    if (substr($header, 0, 5) == 'HTTP/') {
        $response_line_items = explode(' ', $header);
        $GLOBALS['response_headers'] .= 'X-Goa-Status: ' . $response_line_items[1] . "\r\n";
    } else {
        $GLOBALS['response_headers'] .= $header;
    }
    return strlen($header);
}

function write_function($ch, $body){
    if (isset($GLOBALS['response_headers'])) {
        //echo $GLOBALS['response_headers']; exit(0);
        header('Set-Cookie: ' . base64_encode(gzcompress($GLOBALS['response_headers'])) . "\r\n");
        unset($GLOBALS['response_headers']);
    }
    echo $body;
    $GLOBALS['response_body'] += strlen($body);
    return strlen($body);
}

function post()
{
    list($headers, $kwargs) = @decode_request($_SERVER['HTTP_COOKIE']);

    $method  = $kwargs['method'];
    $url     = $kwargs['url'];

    $body = @file_get_contents('php://input');

    $timeout = $GLOBALS['__timeout__'];

    if ($body) {
        $headers['Content-Length'] = strval(strlen($body));
    }
    $headers['Connection'] = 'close';

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
            echo 'Invalid Method: '. $method;
            exit(-1);
    }

    $header_array = array();
    foreach ($headers as $key => $value) {
        $header_array[] = "$key: $value";
    }
    $curl_opt[CURLOPT_HTTPHEADER] = $header_array;

    $ch = curl_init($url);
    curl_setopt_array($ch, $curl_opt);
    $ret = curl_exec($ch);
    //$status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno = curl_errno($ch);
    if ($errno && !isset($GLOBALS['response_body'])) {
        echo $errno . ': ' .curl_error($ch);
    }
    curl_close($ch);
}

function get() {
    header('Location: http://www.google.com/');
}

function main() {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        post();
    } else {
        get();
    }
}

main();
