<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>Login</title>
    <link rel="stylesheet" href="style.css"/>
</head>
<body>
<?php
require __DIR__ .'/vendor/autoload.php'; 
?>
<?php


setcookie("verifier_c", "", time()-3600,"/");
setcookie("nonce_c", "", time()-3600,"/");
 $scope='openid';
 $serviceId='10000xxxx';
 $aeskey='xxxx59f6-0617-4898-b859-8bb02fexxxxx';
 $redirect_uri='http://localhost/login/dashboard.php';
 $response_type= 'code';
 $code_challenge_method='S256';
 $request_uri='https://epstg.meripehchaan.gov.in/openid/jwt/processJwtAuthGrantRequest.do';

 //$request_uri= 'https://up.epramaan.in/openid/jwt/processJwtAuthGrantRequest.do';
 $state= vsprintf('%s%s-%s-%s-%s-%s%s%s',str_split(bin2hex(random_bytes(16)),4));

 //nonce
 $nonce= bin2hex(random_bytes(16));
 setcookie("nonce_c", "$nonce", time() + 3600, "/");

 //verifier
 $verifier_bytes = random_bytes(64);
 $code_verifier = rtrim(strtr(base64_encode($verifier_bytes), "+/", "-_"), "=");


 setcookie("verifier_c", "$code_verifier", time() + 3600, "/");
 
 
//code challenge
$challenge_bytes = hash("sha256", $code_verifier, true);
$code_challenge = rtrim(strtr(base64_encode($challenge_bytes), "+/", "-_"), "=");
 

 $input=$serviceId.$aeskey.$state.$nonce.$redirect_uri.$scope.$code_challenge;

 //apiHmac
 $apiHmac= hash_hmac('sha256',$input,$aeskey,true);
 $apiHmac = base64_encode($apiHmac);

 echo '<br>';
 
 $url = 'https://epstg.meripehchaan.gov.in/openid/jwt/processJwtAuthGrantRequest.do';

 $finalUrl = $url."?&scope=".$scope."&response_type=".$response_type."&redirect_uri=".$redirect_uri."&state=".$state."&code_challenge_method=".$code_challenge_method."&nonce=".$nonce."&client_id=".$serviceId."&code_challenge=".$code_challenge."&request_uri=".$request_uri."&apiHmac=".$apiHmac;

?>

    <form class="form" method="post" name="login">
        <h1 class="login-title">Login</h1>
        <input type="text" class="login-input" name="username" placeholder="Username" autofocus="true"/>
        <input type="password" class="login-input" name="password" placeholder="Password"/>
        <input type="submit" value="Login" name="submit" class="login-button"/>
       
        <p class="link">Don't have an account? <a href="registration.php">Register Now</a></p>



      <a href=<?php echo $finalUrl ?>>  <input type="button" value="Login with e-Pramaan" class="login-button"/></a>
     
  </form>

</body>
</html>
