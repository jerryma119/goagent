<?php 

$__version__ = "1.5.1";

if ($_SERVER["REQUEST_METHOD"] == "POST") 
{
    post();
}
else
{
    get();
}

function encode_data($dic)
{
    $str = "";
    foreach (new ArrayObject($dic) as $key => $value)
    {
       $str .= "&" . $key. "=" . bin2hex($value);
    }
    return substr($str, 1);
}

function decode_data($qs)
{
    $dic = array();
    foreach (explode("&", $qs) as $kv)
    {
        $pair = explode("=", $kv);
        $key = $pair[0];
        $value = pack("H*", $pair[1]);
        $dic[$key] = $value;
    }
    return $dic;
}

function print_response($status, $headers, $content)
{
    $strheaders = encode_data($headers);
    if (array_key_exists("content-type", $headers) && substr($headers["content-type"], 0, 4) == 'text')
    {
        $data = "1" . gzcompress(pack('NNN', $status, strlen($strheaders), strlen($content)) . $strheaders . $content);
    }
    else
    {
        $data = "0" . pack('NNN', $status, len($strheaders), len($content)) . $strheaders . $content;
    }
    header("Content-Type: image/gif");
    print($data);
}

function print_notify($method, $url, $status, $content)
{
    $content = "<h2>Fetch Server Info</h2><hr noshade='noshade'><p>$method '$url'</p><p>Return Code: $status</p><p>Message: $content</p>";
    $headers = array("content-type" => "text/html");
    print_response($status, $headers, $content);
}

function post()
{
    print_notify("GET", "http://www.g.cn", 403, "just a test!"); 
}

function get()
{
    echo <<<EOF

<html> 
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" /> 
    <title>GoAgent $__version__ is working now</title> 
</head> 
<body> 
    <table width="800" border="0" align="center"> 
        <tr><td align="center"><hr></td></tr> 
        <tr><td align="center"> 
            <b><h1>GoAgent $__version__ is working now</h1></b> 
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
