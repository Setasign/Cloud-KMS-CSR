<?php

use setasign\CloudKmsCsr\Csr;
use setasign\CloudKmsCsr\GoogleCloudKMS;

require_once '../../vendor/autoload.php';

$projectId = 'kms-test-and-development';
$locationId = 'europe-west3';
$keyRingId = 'Demo-Key-Ring-1';
$keyId = 'Software-RSA-4096-PSS-SHA-512';
$versionId = '1';

// create an updater instance
$updater = new GoogleCloudKMS\Updater($projectId, $locationId, $keyRingId, $keyId, $versionId);

// create a new CSR
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
