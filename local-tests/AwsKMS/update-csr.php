<?php

use Aws\Kms\KmsClient;
use setasign\CloudKmsCsr\Csr;
use setasign\CloudKmsCsr\AwsKMS;

require_once '../../vendor/autoload.php';

$region = 'eu-central-1';
$version = 'latest';
$keyId = '3d444f18-0034-4c7d-8215-53dc176ee0bc';
$signatureAlgorithm = 'RSASSA_PSS_SHA_512';

$kmsClient = new KmsClient([
    'region' => $region,
    'version' => $version,
    'http' => []
]);

$updater = new AwsKms\Updater($keyId, $kmsClient);
$updater->setSignatureAlgorithm($signatureAlgorithm);

$csr = Csr::create([
    'commonName' => 'Test and Development',
    'organizationName' => 'Setasign GmbH & Co. KG'
]);
// update it by the key in the KMS
$csr->update($updater);

// verify the CSR
echo 'Verified: ' . ($csr->verify() ? 'YES' : 'NO');
echo "\n\n";

// output PEM encoded CSR
echo $csr->get();
