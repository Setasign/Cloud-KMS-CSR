<?php

use Aws\Kms\KmsClient;
use setasign\CloudKmsCsr\Certificate;
use setasign\CloudKmsCsr\AwsKMS;

require_once '../../vendor/autoload.php';

$region = 'eu-central-1';
$version = 'latest';

$keyIds = [
    'Test-Key-RSA_2048' => '3d444f18-0034-4c7d-8215-53dc176ee0bc',
    'Test-Key-RSA_4096' => 'c910223a-0f7b-44fd-b682-69ae740efd5c',
    'Test-Key-ECC_NIST_P256' => '199cb56e-4e15-4959-85b0-5e8fb5dbd1a7',
    'Test-Key-ECC_NIST_P384' => '3dc76c22-0283-47ae-99b4-b3aba3ae56f7',
    'Test-Key-ECC_NIST_P521' => 'd58649fe-8aa4-476c-aa35-0481643c2c96',
    'Test-Key-ECC_SECG_P256K1' => '9e35b16a-2cc6-46ec-bbb0-fcf96c6ef349' // !!! CANNOT BE VALIDATED BY ACROBAT !!!
];

$kmsClient = new KmsClient([
    'region' => $region,
    'version' => $version
]);

foreach ($keyIds as $alias => $combinations) {

    $keyId = $keyIds[$alias];

    $updater = new AwsKms\Updater($keyId, $kmsClient);

    $pkRresult = $updater->ensurePublicKey();

    foreach ($pkRresult->get('SigningAlgorithms') as $algorithm) {
        $name = $alias . ',' . $algorithm;

        $dn = [
            "countryName" => "DE",
            "stateOrProvinceName" => "Niedersachsen",
            "organizationName" => "Setasign GmbH & Co. KG",
            "commonName" => "Dev. & Test (" . $name . ")",
            "emailAddress" => "setapdf-demos@setasign.com"
        ];

        $certificate = Certificate::create($dn);

        $updater->setSignatureAlgorithm($algorithm);

        // update it by the key in the KMS
        $certificate->update($updater);

        var_dump($certificate->get());
        var_dump($certificate->verify());

        file_put_contents(__DIR__ . '/certs/' . $name . '.crt', $certificate->get());
    }
}
