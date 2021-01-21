<?php

use setasign\CloudKmsCsr\Certificate;
use setasign\CloudKmsCsr\GoogleCloudKMS;

require_once '../../vendor/autoload.php';

$projectId = 'kms-test-and-development';
$locationId = 'europe-west3';
$keyRingId = 'Demo-Key-Ring-1';
$keyId = 'Software-RSA-4096-PSS-SHA-512';
$versionId = '1';

// create an updater instance
$updater = new GoogleCloudKMS\Updater($projectId, $locationId, $keyRingId, $keyId, $versionId);

// create a new Certificate
$certificate = Certificate::create([
    'commonName' => 'Test and Development',
    'organizationName' => 'Setasign GmbH & Co. KG'
]);
// update it by the key in the KMS
$certificate->update($updater);

// verify the certifcate
echo 'Verified: ' . ($certificate->verify() ? 'YES' : 'NO');
echo "\n\n";

// output PEM encoded certifcate
echo $certificate->get();
