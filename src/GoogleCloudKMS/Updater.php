<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\CloudKmsCsr\GoogleCloudKMS;

use setasign\CloudKmsCsr\Exception;
use setasign\CloudKmsCsr\UpdaterInterface;
use Google\ApiCore\ApiException;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Google\Cloud\Kms\V1\CryptoKeyVersion\CryptoKeyVersionAlgorithm;
use Google\Cloud\Kms\V1\Digest as KmsDigest;
use SetaPDF_Signer_Digest as Digest;

class Updater implements UpdaterInterface
{
    /**
     * @var KeyManagementServiceClient
     */
    protected $kmsClient;

    /**
     * @var string
     */
    protected $keyVersionName;

    /**
     * @var string
     */
    protected $publicKey;

    /**
     * @param string $projectId
     * @param string $locationId
     * @param string $keyRingId
     * @param string $keyId
     * @param string $versionId
     * @param KeyManagementServiceClient|null $client
     */
    public function __construct(
        $projectId,
        $locationId,
        $keyRingId,
        $keyId,
        $versionId,
        KeyManagementServiceClient $client = null
    ) {
        $this->keyVersionName = KeyManagementServiceClient::cryptoKeyVersionName(
            $projectId,
            $locationId,
            $keyRingId,
            $keyId,
            $versionId
        );

        $this->kmsClient = $client !== null ? $client : new KeyManagementServiceClient();
    }

    /**
     * @inheritDoc
     * @throws Exception
     * @throws ApiException
     */
    public function getDigest()
    {
        $algorithm = $this->ensurePublicKey()->getAlgorithm();
        switch ($algorithm) {
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_2048_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_3072_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_4096_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_2048_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_3072_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA256:
            case CryptoKeyVersionAlgorithm::EC_SIGN_P256_SHA256:
                return Digest::SHA_256;
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_4096_SHA512:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512:
                return Digest::SHA_512;
            case CryptoKeyVersionAlgorithm::EC_SIGN_P384_SHA384:
                return Digest::SHA_384;
            default:
                throw new Exception('Unknown algorithm id "%d".', $algorithm);
        }
    }

    /**
     * @inheritDoc
     * @throws Exception
     * @throws ApiException
     */
    public function getAlgorithm()
    {
        $algorithm = $this->ensurePublicKey()->getAlgorithm();
        switch ($algorithm) {
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_2048_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_3072_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_4096_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_4096_SHA512:
                return Digest::RSA_ALGORITHM;
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_2048_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_3072_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512:
                return Digest::RSA_PSS_ALGORITHM;
            case CryptoKeyVersionAlgorithm::EC_SIGN_P256_SHA256:
            case CryptoKeyVersionAlgorithm::EC_SIGN_P384_SHA384:
                return Digest::ECDSA_ALGORITHM;
            default:
                throw new Exception('Unknown algorithm id "%d".', $algorithm);
        }
    }

    /**
     * @inheritDoc
     * @see https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
     * @throws ApiException
     */
    public function getPssSaltLength()
    {
        // "For Probabilistic Signature Scheme (PSS), the salt length used is equal to the length of the digest
        // algorithm. For example, RSA_SIGN_PSS_2048_SHA256 will use PSS with a salt length of 256 bits."
        $algorithm = $this->ensurePublicKey()->getAlgorithm();
        switch ($algorithm) {
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_2048_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_3072_SHA256:
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA256:
                return 256 / 8;
            case CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512:
                return 512 / 8;
            default:
                throw new \BadMethodCallException('The algorithm does not support PSS padding.');
        }
    }

    /**
     * Ensures that the public key and related information are loaded and returned.
     *
     * @return \Google\Cloud\Kms\V1\PublicKey
     * @throws ApiException
     */
    protected function ensurePublicKey()
    {
        if ($this->publicKey === null) {
            $this->publicKey = $this->kmsClient->getPublicKey($this->keyVersionName);
        }

        return $this->publicKey;
    }

    /**
     * @inheritDoc
     * @throws ApiException
     */
    public function getPublicKey()
    {
        return $this->ensurePublicKey()->getPem();
    }

    /**
     * @inheritDoc
     * @throws ApiException|Exception
     */
    public function sign($data)
    {
        $digest = $this->getDigest();
        $hash = \hash($digest, $data, true);
        $digestValue = new KmsDigest();
        switch ($digest) {
            case Digest::SHA_256:
                $digestValue->setSha256($hash);
                break;
            case Digest::SHA_384:
                $digestValue->setSha384($hash);
                break;
            case Digest::SHA_512:
                $digestValue->setSha512($hash);
                break;
        }

        $signResponse = $this->kmsClient->asymmetricSign($this->keyVersionName, $digestValue);

        return $signResponse->getSignature();
    }
}
