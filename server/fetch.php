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

function post()
{
}

function get()
{
    echo <<<EOF

<html> 
<head> 
    <link rel="icon" type="image/vnd.microsoft.icon" href="https://ssl.gstatic.com/codesite/ph/images/phosting.ico"> 
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
