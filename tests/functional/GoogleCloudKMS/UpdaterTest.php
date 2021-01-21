<?php

namespace setasign\CloudKmsCsr\tests\functional\GoogleCloudKMS;

use PHPUnit\Framework\TestCase;
use setasign\CloudKmsCsr\Certificate;
use setasign\CloudKmsCsr\GoogleCloudKMS\Updater;
use setasign\CloudKmsCsr\Csr;

class UpdaterTest extends TestCase
{
    public function updaterProvider()
    {
        return [
            ['Software-RSA-2048-PKCS1-SHA-256'],
            ['Software-RSA-2048-PSS-SHA-256'],
            ['Software-RSA-4096-PSS-SHA-512'],
            ['Software-EC-P-256-SHA-256'],
            ['Software-EC-P-384-SHA-384']
        ];
    }

    /**
     * @param $keyId
     * @param $signatureAlgorithm
     * @param string $region
     * @param string $version
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws \setasign\CloudKmsCsr\Exception
     * @dataProvider updaterProvider
     */
    public function testCsrUpdate($keyId)
    {
        $projectId = 'kms-test-and-development';
        $locationId = 'europe-west3';
        $keyRingId = 'Demo-Key-Ring-1';
        $versionId = '1';

        $updater = new Updater($projectId, $locationId, $keyRingId, $keyId, $versionId);

        $csr = Csr::create(['commonName' => 'Tester']);
        $csr->update($updater);

        $this->assertTrue($csr->verify());

        // use this to manually verify the CSR by OpenSSL CLI
//        $tmpFile = \SetaPDF_Core_Writer_TempFile::createTempFile($csr->get());
//        $openSslPath = 'C:\\OpenSSL\\Win64-1.1.1i\\bin\\';
//        $cmd = $openSslPath . 'openssl req -in ' . escapeshellarg($tmpFile). ' -noout -verify';
//        shell_exec($cmd);
    }

    /**
     * @param $keyId
     * @param $signatureAlgorithm
     * @param string $region
     * @param string $version
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws \setasign\CloudKmsCsr\Exception
     * @dataProvider updaterProvider
     */
    public function testCertificateUpdate($keyId)
    {
        $projectId = 'kms-test-and-development';
        $locationId = 'europe-west3';
        $keyRingId = 'Demo-Key-Ring-1';
        $versionId = '1';

        $updater = new Updater($projectId, $locationId, $keyRingId, $keyId, $versionId);

        $certificate = Certificate::create(['commonName' => 'Tester']);
        $certificate->update($updater);

        $this->assertTrue($certificate->verify());
    }
}