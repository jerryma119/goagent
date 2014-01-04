<?php

$__relay__ = 'http://goagent.app.com/index.php';
$__hosts__ = array('goagent.app.com');
$__timeout__ = 16;


function php_getallheaders() {
    $headers = array();
    foreach ($_SERVER as $name => $value) {
        if (substr($name, 0, 5) == 'HTTP_')  {
            $name = join('-', array_map('ucfirst', explode('_', strtolower(substr($name, 5)))));
            $headers[$name] = $value;
        } else if ($name == "CONTENT_TYPE") {
            $headers["Content-Type"] = $value;
        } else if ($name == "CONTENT_LENGTH") {
            $headers["Content-Length"] = $value;
        }
    }
    return $headers;
}


function header_function($ch, $header) {
    header($header);
    return strlen($header);
}


function write_function($ch, $content) {
    echo $content;
    return strlen($content);
}


function post() {
    $url = $GLOBALS['__relay__'];
    $host = $GLOBALS['__hosts__'][array_rand($GLOBALS['__hosts__'])];
    $headers = php_getallheaders();
    $body = $GLOBALS['HTTP_RAW_POST_DATA'];

    $urlparts = parse_url($url);

    if ($body && !isset($headers['Content-Length'])) {
        $headers['Content-Length'] = strval(strlen($body));
    }
    $headers['Connection'] = 'close';
    $headers['Host'] = $urlparts['host'];

    $header_array = array();
    foreach ($headers as $key => $value) {
        $header_array[] = "$key: $value";
    }

    $timeout = $GLOBALS['__timeout__'];

    $curl_opt = array();

    $curl_opt[CURLOPT_POST] = true;
    $curl_opt[CURLOPT_POSTFIELDS] = $body;

    $curl_opt[CURLOPT_HTTPHEADER] = $header_array;
    $curl_opt[CURLOPT_RETURNTRANSFER] = true;
    $curl_opt[CURLOPT_BINARYTRANSFER] = true;

    $curl_opt[CURLOPT_HEADER]         = false;
    $curl_opt[CURLOPT_HEADERFUNCTION] = 'header_function';
    $curl_opt[CURLOPT_WRITEFUNCTION]  = 'write_function';

    $curl_opt[CURLOPT_FAILONERROR]    = false;
    $curl_opt[CURLOPT_FOLLOWLOCATION] = false;

    $curl_opt[CURLOPT_CONNECTTIMEOUT] = $timeout;
    $curl_opt[CURLOPT_TIMEOUT]        = $timeout;

    $curl_opt[CURLOPT_SSL_VERIFYPEER] = false;
    $curl_opt[CURLOPT_SSL_VERIFYHOST] = false;

    $newurl = preg_replace('@//[^/]+@', "//$host", $url) . '?' . $_SERVER['QUERY_STRING'];

    //var_dump(array('newurl' => $newurl, 'headers' => $headers, 'curl_opt' => $curl_opt));
    //exit(0);

    $ch = curl_init($newurl);
    curl_setopt_array($ch, $curl_opt);
    $ret = curl_exec($ch);
    $errno = curl_errno($ch);

    if ($errno) {
        if (!headers_sent()) {
            header('Content-Type: text/plain');
        }
        echo "HTTP/1.0 502\r\nContent-Type: text/plain\r\n\r\n";
        echo "502 Urlfetch Error\r\nPHP Urlfetch Error: curl($errno)\r\n"  . curl_error($ch);
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
