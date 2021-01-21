<?php

namespace setasign\CloudKmsCsr\AwsKMS;

use Aws\Kms\KmsClient;
use setasign\CloudKmsCsr\Exception;
use setasign\CloudKmsCsr\UpdaterInterface;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Pem as Pem;

class Updater implements UpdaterInterface
{
    /**
     * @var KmsClient
     */
    protected $kmsClient;

    /**
     * @var string
     */
    protected $keyId;

    /**
     * @var string|null
     */
    protected $signatureAlgorithm;

    /**
     * @var
     */
    protected $publicKey;

    /**
     * @param string $keyId
     * @param KmsClient $kmsClient
     */
    public function __construct($keyId, KmsClient $kmsClient)
    {
        $this->keyId = $keyId;
        $this->kmsClient = $kmsClient;
    }

    /**
     * Set the signature algorithm to use with the stored key.
     *
     * @see https://cloud.google.com/kms/docs/reference/rest/v1/CryptoKeyVersionAlgorithm
     * @param string $signatureAlgorithm
     */
    public function setSignatureAlgorithm($signatureAlgorithm)
    {
        $publicKey = $this->ensurePublicKey();
        if (!in_array($signatureAlgorithm, $publicKey->get('SigningAlgorithms'), true)) {
            throw new \InvalidArgumentException(
                \sprintf('Signature algorithm "%s" is not supported by key.', $signatureAlgorithm)
            );
        }

        $this->signatureAlgorithm = $signatureAlgorithm;
    }

    /**
     * Get the signature algorithm to use with the stored key.
     *
     * @see https://cloud.google.com/kms/docs/reference/rest/v1/CryptoKeyVersionAlgorithm
     * @return string
     */
    public function getSignatureAlgorithm()
    {
        if ($this->signatureAlgorithm === null) {
            throw new \BadMethodCallException('Signature algorithm is not set.');

        }
        return $this->signatureAlgorithm;
    }

    /**
     * @inheritDoc
     * @throws Exception
     */
    public function getDigest()
    {
        $algorithm = $this->getSignatureAlgorithm();
        switch ($algorithm) {
            case 'RSASSA_PKCS1_V1_5_SHA_256':
            case 'RSASSA_PSS_SHA_256':
            case 'ECDSA_SHA_256':
                return Digest::SHA_256;
            case 'RSASSA_PKCS1_V1_5_SHA_384':
            case 'RSASSA_PSS_SHA_384':
            case 'ECDSA_SHA_384':
                return Digest::SHA_384;
            case 'RSASSA_PKCS1_V1_5_SHA_512':
            case 'RSASSA_PSS_SHA_512':
            case 'ECDSA_SHA_512':
                return Digest::SHA_512;
            default:
                throw new Exception('Unknown algorithm "%s".', $algorithm);
        }
    }

    /**
     * @inheritDoc
     * @throws Exception
     */
    public function getAlgorithm()
    {
        $algorithm = $this->getSignatureAlgorithm();
        switch ($algorithm) {
            case 'RSASSA_PKCS1_V1_5_SHA_256':
            case 'RSASSA_PKCS1_V1_5_SHA_384':
            case 'RSASSA_PKCS1_V1_5_SHA_512':
                return Digest::RSA_ALGORITHM;
            case 'RSASSA_PSS_SHA_256':
            case 'RSASSA_PSS_SHA_384':
            case 'RSASSA_PSS_SHA_512':
                return Digest::RSA_PSS_ALGORITHM;
            case 'ECDSA_SHA_256':
            case 'ECDSA_SHA_384':
            case 'ECDSA_SHA_512':
                return Digest::ECDSA_ALGORITHM;
            default:
                throw new Exception('Unknown algorithm "%s".', $algorithm);
        }
    }

    /**
     * @inheritDoc
     * @see https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose.html
     */
    public function getPssSaltLength()
    {
        // E.g.: "PKCS #1 v2.2, Section 8.1, RSA signature with PSS padding using SHA-256 for both the message
        // digest and the MGF1 mask generation function along with a 256-bit salt"
        $algorithm = $this->getSignatureAlgorithm();
        switch ($algorithm) {
            case 'RSASSA_PSS_SHA_256':
                return 256 / 8;
            case 'RSASSA_PSS_SHA_384':
                return 384 / 8;
            case 'RSASSA_PSS_SHA_512':
                return 512 / 8;
            default:
                throw new \BadMethodCallException('The key does not support PSS padding.');
        }
    }

    /**
     * Ensures that the public key and related information are loaded and returned.
     *
     * @return \Aws\Result
     */
    public function ensurePublicKey()
    {
        if ($this->publicKey === null) {
            $this->publicKey = $this->kmsClient->getPublicKey([
                'KeyId' => $this->keyId
            ]);
        }

        return $this->publicKey;
    }

    /**
     * @inheritDoc
     */
    public function getPublicKey()
    {
        return Pem::encode($this->ensurePublicKey()->get('PublicKey'), 'PUBLIC KEY');
    }

    /**
     * @inheritDoc
     * @throws Exception
     */
    public function sign($data)
    {
        $result = $this->kmsClient->sign([
            'KeyId' => $this->keyId,
            'Message' => hash($this->getDigest(), $data, true),
            'MessageType' => 'DIGEST',
            'SigningAlgorithm' => $this->getSignatureAlgorithm()
        ]);

        return $result->get('Signature');
    }
}
