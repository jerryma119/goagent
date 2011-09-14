<?php 

$__version__ = "1.5.1";
$__password__ = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    post();
} else {
    get();
}

function encode_data($dic) {
    $str = "";
    foreach ($dic as $key => $value) {
       $str .= "&" . $key. "=" . bin2hex($value);
    }
    return substr($str, 1);
}

function decode_data($qs) {
    $dic = array();
    foreach (explode("&", $qs) as $kv) {
        $pair = explode("=", $kv);
        $key = $pair[0];
        $value = pack("H*", $pair[1]);
        $dic[$key] = $value;
    }
    return $dic;
}

function print_response($status, $headers, $content) {
    $strheaders = encode_data($headers);
    if (array_key_exists("content-type", $headers) && substr($headers["content-type"], 0, 4) == 'text') {
        $data = "1" . gzcompress(pack('NNN', $status, strlen($strheaders), strlen($content)) . $strheaders . $content);
    } else {
        $data = "0" . pack('NNN', $status, strlen($strheaders), strlen($content)) . $strheaders . $content;
    }
    header("Content-Type: image/gif");
    header("Content-Length: ".strlen($data));
    print($data);
}

function print_notify($method, $url, $status, $content) {
    $content = "<h2>Fetch Server Info</h2><hr noshade='noshade'><p>$method '$url'</p><p>Return Code: $status</p><p>Message: $content</p>";
    $headers = array("content-type" => "text/html");
    print_response($status, $headers, $content);
}

$__urlfetch_headers = array();
function urlfetch_header_callabck($ch, $header) {
    global $__urlfetch_headers;
    
    $kv = array_map('trim', explode(':', $header, 2));
    $__urlfetch_headers[$kv[0]] = $kv[1];
	return strlen($header);
}

function urlfetch($url, $payload, $method, $headers, $follow_redirects, $deadline, $validate_certificate) {
    global $__urlfetch_headers;
    
    $__urlfetch_headers = array();
    
    if ($payload) {
        $headers["content-length"] = strval(strlen($data));
    }
    $headers["connection"] = 'close';
    
    $curl_opt = array();
    
    $curl_opt[CURLOPT_TIMEOUT]        = $deadline;
    $curl_opt[CURLOPT_CONNECTTIMEOUT] = $deadline;
	$curl_opt[CURLOPT_RETURNTRANSFER] = True;
	$curl_opt[CURLOPT_BINARYTRANSFER] = True;
	$curl_opt[CURLOPT_FAILONERROR]    = True;
	
    if (!$follow_redirects) {
	    $curl_opt[CURLOPT_FOLLOWLOCATION] = False;
	}
    
    if (!$validate_certificate) {
	    $curl_opt[CURLOPT_SSL_VERIFYPEER] = False;
	    $curl_opt[CURLOPT_SSL_VERIFYHOST] = False;
	}
	
	switch ($method) {
		case 'HEAD':
			$curl_opt[CURLOPT_NOBODY] = True;
			break;
		case 'GET':
			break;
		case 'PUT':
		case 'POST':
		case 'DELETE':
			$curl_opt[CURLOPT_CUSTOMREQUEST] = $method;
			$curl_opt[CURLOPT_POSTFIELDS] = $payload;
			break;
		default:
		    print_notify($method, $url, 403, "Invalid Method"); 
		    exit(-1);
	}
	
	foreach ($headers as $key => $value) {
	    $curl_opt[CURLOPT_HTTPHEADER][$key] = $key.'= '.$value;
	}
	
	$curl_opt[CURLOPT_HEADERFUNCTION] = 'urlfetch_header_callabck';
	
    $ch = curl_init($url);
    curl_setopt_array($ch, $curl_opt);
    $content = curl_exec($ch);
    $__urlfetch_headers["connection"] = 'close';
    $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
 
    $response = array('status_code' => $status_code, 'headers' => $__urlfetch_headers, 'content' => $content);
    return $response;
}

function post()
{
    global $__password__;
    
    $request = @gzuncompress(@file_get_contents('php://input'));
    if ($request === False) {
		return print_notify($method, $url, 403, 'OOPS! gzuncompress php://input error!');
	}
    $request = decode_data($request);
    
    $method  = $request['method'];
    $url     = $request['url'];
    $payload = $request['payload'];
    
    if ($__password__ && $__password__ != $request['password']) {
        return print_notify($method, $url, 403, 'Wrong password.');
    }
    
    if (substr($url, 0, 4) != 'http') {
        return print_notify($method, $url, 501, 'Unsupported Scheme');
    }
    
    $FetchMax     = 3;
    $FetchMaxSize = 1024*1024;
    $Deadline     = array(0 => 16, 1 => 32);
    $deadline     = $Deadline[0];
    
    $headers = array();
    foreach (explode("\r\n", $request['headers']) as $line) {
        $pair = explode(":", $line);
        $headers[trim($pair[0])] = trim($pair[1]);
    }
    $headers['connection'] = 'close';
    
    $fetchrange = 'bytes=0-' . strval($FetchMaxSize - 1);
    if (array_key_exists('range', $headers)) {
        preg_match('/(\d+)?-(\d+)?/', $headers['range'], $matches, PREG_OFFSET_CAPTURE);
        $start = $matches[1][0];
        $end = $matches[2][0];
        if ($start || $end) {
            if (!$start and intval($end) > $FetchMaxSize) {
                $end = '1023';
            }
            else if (!$end || intval($end)-intval($start)+1 > $FetchMaxSize) {
                $end = strval($FetchMaxSize-1+intval($start));
            }
            $fetchrange = 'bytes='.$start.'-'.$end;
        }
    }
    
    $errors = array();
    for ($i = 0; $i < $FetchMax; $i++) {
        $response = urlfetch($url, $payload, $method, $headers, False, $deadline, False);
        $status_code = $response['status_code'];
        if (200 <= $status_code && $status_code < 400) {
           return print_response($status_code, $response['headers'], $response['content']);
        }
    }
    
    print_notify($request["method"], $request["url"], 403, "Fetch Server Failed!!!"); 
}

function get() {
    global $__version__;
    
    echo <<<EOF

<html> 
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> 
    <title>GoAgent {$__version__} is working now</title> 
</head> 
<body> 
    <table width="800" border="0" align="center"> 
        <tr><td align="center"><hr></td></tr> 
        <tr><td align="center"> 
            <b><h1>GoAgent {$__version__} is working now</h1></b> 
        </td></tr> 
        <tr><td align="center"><hr></td></tr> 
 
        <tr><td align="center"> 
            GoAgent is HTTP Porxy written by python and hosting in google appengine.
        </td></tr> 
        <tr><td align="center"><hr></td></tr> 
 
        <tr><td align="center"> 
            For more detail,please refer to <a href="http://code.google.com/p/goagent/">GoAgent Project Homepage</a>.
        </td></tr> 
        <tr><td align="center"><hr></td></tr> 
    </table> 
</body>

EOF;
}
