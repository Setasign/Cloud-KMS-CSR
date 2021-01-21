<?php

namespace setasign\CloudKmsCsr\tests\functional\AwsKMS;

use Aws\Kms\KmsClient;
use PHPUnit\Framework\TestCase;
use setasign\CloudKmsCsr\AwsKMS\Updater;
use setasign\CloudKmsCsr\Certificate;
use setasign\CloudKmsCsr\Csr;

class UpdaterTest extends TestCase
{
    public function updaterProvider()
    {
        return [
            // Test-Key-RSA_2048
            ['3d444f18-0034-4c7d-8215-53dc176ee0bc', 'RSASSA_PKCS1_V1_5_SHA_256'],
            ['3d444f18-0034-4c7d-8215-53dc176ee0bc', 'RSASSA_PKCS1_V1_5_SHA_384'],
            ['3d444f18-0034-4c7d-8215-53dc176ee0bc', 'RSASSA_PKCS1_V1_5_SHA_512'],
            ['3d444f18-0034-4c7d-8215-53dc176ee0bc', 'RSASSA_PSS_SHA_256'],
            ['3d444f18-0034-4c7d-8215-53dc176ee0bc', 'RSASSA_PSS_SHA_384'],
            ['3d444f18-0034-4c7d-8215-53dc176ee0bc', 'RSASSA_PSS_SHA_512'],

            // Test-Key-RSA_4096
            ['c910223a-0f7b-44fd-b682-69ae740efd5c', 'RSASSA_PKCS1_V1_5_SHA_256'],
            ['c910223a-0f7b-44fd-b682-69ae740efd5c', 'RSASSA_PKCS1_V1_5_SHA_384'],
            ['c910223a-0f7b-44fd-b682-69ae740efd5c', 'RSASSA_PKCS1_V1_5_SHA_512'],
            ['c910223a-0f7b-44fd-b682-69ae740efd5c', 'RSASSA_PSS_SHA_256'],
            ['c910223a-0f7b-44fd-b682-69ae740efd5c', 'RSASSA_PSS_SHA_384'],
            ['c910223a-0f7b-44fd-b682-69ae740efd5c', 'RSASSA_PSS_SHA_512'],

            // Test-Key-ECC_NIST_P256
            ['199cb56e-4e15-4959-85b0-5e8fb5dbd1a7', 'ECDSA_SHA_256'],

            // Test-Key-ECC_NIST_P384
            ['3dc76c22-0283-47ae-99b4-b3aba3ae56f7', 'ECDSA_SHA_384'],

            // Test-Key-ECC_NIST_P521
            ['d58649fe-8aa4-476c-aa35-0481643c2c96', 'ECDSA_SHA_512'],

            // Test-Key-ECC_SECG_P256K1
            ['9e35b16a-2cc6-46ec-bbb0-fcf96c6ef349', 'ECDSA_SHA_256'],
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
    public function testCsrUpdate($keyId, $signatureAlgorithm, $region = 'eu-central-1', $version = 'latest')
    {
        $kmsClient = new KmsClient([
            'region' => $region,
            'version' => $version,
            'http' => []
        ]);

        $updater = new Updater($keyId, $kmsClient);
        $updater->setSignatureAlgorithm($signatureAlgorithm);

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
    public function testCertificateUpdate($keyId, $signatureAlgorithm, $region = 'eu-central-1', $version = 'latest')
    {
        $kmsClient = new KmsClient([
            'region' => $region,
            'version' => $version,
            'http' => []
        ]);

        $updater = new Updater($keyId, $kmsClient);
        $updater->setSignatureAlgorithm($signatureAlgorithm);

        $certificate = Certificate::create(['commonName' => 'Tester']);
        $certificate->update($updater);

        $this->assertTrue($certificate->verify());
    }

    public function updateWithInvalidAlgorithmProvider()
    {
        return [
            ['3d444f18-0034-4c7d-8215-53dc176ee0bc', 'ECDSA_SHA_256'],
            ['199cb56e-4e15-4959-85b0-5e8fb5dbd1a7', 'RSASSA_PKCS1_V1_5_SHA_256'],
            ['199cb56e-4e15-4959-85b0-5e8fb5dbd1a7', 'ECDSA_SHA_384'],
            ['d58649fe-8aa4-476c-aa35-0481643c2c96', 'ECDSA_SHA_256'],
        ];
    }

    /**
     * @param $keyId
     * @param $signatureAlgorithm
     * @param string $region
     * @param string $version
     * @dataProvider updateWithInvalidAlgorithmProvider
     */
    public function testUpdaterWithInvalidAlgorithm(
        $keyId, $signatureAlgorithm, $region = 'eu-central-1', $version = 'latest'
    )
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(\sprintf('Signature algorithm "%s"', $signatureAlgorithm));

        $kmsClient = new KmsClient([
            'region' => $region,
            'version' => $version,
            'http' => []
        ]);

        $updater = new Updater($keyId, $kmsClient);
        $updater->setSignatureAlgorithm($signatureAlgorithm);
        $updater->sign('anything');
    }
}