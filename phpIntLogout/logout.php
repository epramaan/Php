<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>Logout</title>
    <link rel="stylesheet" href="style.css"/>
</head>
<body>
<?php
require __DIR__ .'/vendor/autoload.php';

session_start(); 
$payload1= $_COOKIE["payload_c"];
echo 'payload--' .$payload1;
echo '<br>';
$data=json_decode($payload1);
$sessionId=$data->session_id;
$sub=$data->sub; 
$clientId='10000xxxx';
$iss='ePramaan';
$aeskey='xxxx59f6-0617-48xx-b859-8bb02feexxxx';
   if (!isset($_SESSION['logoutRequestId'])) {
    $_SESSION['logoutRequestId'] = bin2hex(random_bytes(16));
}
$logoutRequestId = $_SESSION['logoutRequestId'];
   echo 'logout req id--'.$logoutRequestId;
   $redirectUrl='http://localhost/login/login.php';
   
   $input=$clientId.$sessionId.$iss.$aeskey.$sub.$redirectUrl;
 
   echo 'input-->'.$input;
    $apiHmac=hashHMACHex($aeskey,$input);
   echo '<br>';
   $customParameter='';
   

function hashHMACHex($hMACKey, $inputValue) {
  $keyByte = utf8_encode($hMACKey);
  $messageBytes = utf8_encode($inputValue);
  
  $hash = hash_hmac('sha256', $messageBytes, $keyByte, true);
  
  return base64_encode($hash);
}

  
$data = array(
  'clientId' => $clientId,
  'sessionId' => $sessionId,
  'hmac' => $apiHmac,
  'iss' => $iss,
  'logoutRequestId' => $logoutRequestId,
  'sub' => $sub,
  'redirectUrl' => $redirectUrl,
  'customParameter' => $customParameter
);

$dataJson = json_encode($data);

$url = 'https://epstg.meripehchaan.gov.in/openid/jwt/processOIDCSLORequest.do';


echo 'datajson--'. htmlspecialchars($dataJson);

?>

<form method="post" action="<?php echo $url ; ?>">
  <input type="hidden" name="data" value="<?php echo htmlspecialchars($dataJson); ?>">
  <input type="submit" value="logout">
</form>


</body>
 </html>




 
