<?php

require __DIR__ .'/vendor/autoload.php';

use Jose\Component\Encryption\JWEDecrypterFactory;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;

use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Encryption\Serializer\CompactSerializer;

use Jose\Component\Encryption\JWEDecrypter;

use Jose\Component\Encryption\JWELoader;

setcookie("decryptedtoken_c", "", time()-3600,"/");
 $code =htmlspecialchars($_GET["code"]) ;
echo $code;
echo "------------------------------";

$verifier = $_COOKIE["verifier_c"];

echo "<br/>";
 $nonce=$_COOKIE["nonce_c"];
$epramaanRequestTokenUrl='https://epstg.meripehchaan.gov.in/openid/jwt/processJwtTokenRequest.do';
$grant_type='authorization_code';
$scope='openid';
$redirect_uri='http://localhost/login/login.php';
$service_id='10000xxxx';

$curl = curl_init();

curl_setopt_array($curl, array(
  CURLOPT_URL => $epramaanRequestTokenUrl,
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_SSL_VERIFYHOST=> 0,
  CURLOPT_SSL_VERIFYPEER=>0,
  CURLOPT_CUSTOMREQUEST => 'POST',
  CURLOPT_POSTFIELDS =>'{
    "code":["'.$code.'"], 
    "grant_type":["'.$grant_type.'"], 
    "scope":["'.$scope.'"], 
    "redirect_uri":["'.$redirect_uri.'"], 
    "request_uri":["'.$epramaanRequestTokenUrl.'"],
    "code_verifier":["'.$verifier.'"], 
    "client_id":["'.$service_id.'"]
}',
  CURLOPT_HTTPHEADER => array(
    'Content-Type: application/json',
 
  ),

));

 $response = curl_exec($curl);

curl_close($curl);

echo $response;
//---------processing token-decrypt--------------


// The key encryption algorithm manager with the A256KW algorithm.
$keyEncryptionAlgorithmManager = new AlgorithmManager([
    new A256KW(),
      
    ]);
    
    // The content encryption algorithm manager with the A256CBC-HS256 algorithm.
    $contentEncryptionAlgorithmManager = new AlgorithmManager([
        new A256GCM(),
    ]);
    
    $compressionMethodManager = new CompressionMethodManager([
        new Deflate(),
    
    ]);
  $nonce=$_COOKIE["nonce_c"];
  echo '<br>';

  $sha25=hash('SHA256',$nonce,true);
  
  var_dump($sha25);
  
  echo '<br>';
  function base64url_encode($data)
  {
  // First of all you should encode $data to Base64 string
  $b64 = base64_encode($data);
  
  // Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
  $url = strtr($b64, '+/', '-_');
  
  // Remove padding character from the end of line and return the Base64URL result
  return rtrim($url, '=');
  }
  $jwk = new JWK([
    'kty' => 'oct',
    'k' => base64url_encode($sha25),
  ]);
  echo '<br>';
  //decryption
  $jweDecrypter = new JWEDecrypter(
    $keyEncryptionAlgorithmManager,
    $contentEncryptionAlgorithmManager,
    $compressionMethodManager
  );
  
  // The serializer manager. We only use the JWE Compact Serialization Mode.
  $serializerManager = new JWESerializerManager([
    new CompactSerializer(),
  ]);
  // We try to load the token.
  $jwe = $serializerManager->unserialize($response);
  // We decrypt the token. This method does NOT check the header.
  $success = $jweDecrypter->decryptUsingKey($jwe, $jwk, 0);
  
  if ($success) {
    $jweLoader = new JWELoader(
        $serializerManager,
        $jweDecrypter,
        null
    );
    $jwe = $jweLoader->loadAndDecryptWithKey($response, $jwk, $recipient);
    $decryptedtoken=$jwe->getPayload();
    echo $decryptedtoken;
    setcookie("decryptedtoken_c", "$decryptedtoken", time() + 3600, "/");
    
  }
  else {
    throw new RuntimeException('Error Decrypting JWE');
  }
  
  echo '<br>';

  echo '<br>';
  
  echo '<br>';
  
  echo '<br>';
  
  header("Location: verify.php");
  
  
?>