<?php
require __DIR__ .'/vendor/autoload.php';
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSLoader;

$decryptedtoken1  = $_COOKIE["decryptedtoken_c"];
echo '<br>';
echo $decryptedtoken1;
echo '<br>';

$algorithmManager = new AlgorithmManager([
    new RS256(),
]);


$jwsVerifier = new JWSVerifier(
    $algorithmManager
);

$key = JWKFactory::createFromCertificateFile(
    'C:\nssoFiles\epramaanStaging.cer', // The certificate path
    [
        'use' => 'sig',         // Additional parameters
    ]
);

  $serializerManager = new JWSSerializerManager([
      new CompactSerializer(),
 ]);

 $jws = $serializerManager->unserialize($decryptedtoken1);

 $isVerified = $jwsVerifier->verifyWithKey($jws, $key, 0);
 

 echo '<br>';


$jwsLoader = new JWSLoader(
    $serializerManager,
    $jwsVerifier,
    null
);

 $jws = $jwsLoader->loadAndVerifyWithKey($decryptedtoken1, $key, $signature);
 $payload=$jws->getPayload();
echo $payload;
echo '<br>';
echo '<br>';
$data=json_decode($payload);
echo 'Name--' .$data->name;
echo '<br>';
echo 'Username--' .$data->username;
echo '<br>';


?>