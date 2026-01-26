<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\CloudKmsCsr\GoogleCloudKMS;

use Google\Cloud\Kms\V1\PublicKey as GcKmsPublicKey;
use setasign\CloudKmsCsr\Exception;
use setasign\CloudKmsCsr\UpdaterInterface;
use Google\ApiCore\ApiException;
use Google\Cloud\Kms\V1\KeyManagementServiceClient;
use Google\Cloud\Kms\V1\CryptoKeyVersion\CryptoKeyVersionAlgorithm;
use Google\Cloud\Kms\V1\Digest as KmsDigest;
use setasign\SetaPDF2\Signer\Digest;

class Updater implements UpdaterInterface
{
    protected KeyManagementServiceClient $kmsClient;
    protected string $keyVersionName;
    protected ?GcKmsPublicKey $publicKey = null;

    /**
     * @param string $projectId
     * @param string $locationId
     * @param string $keyRingId
     * @param string $keyId
     * @param string $versionId
     * @param KeyManagementServiceClient|null $client
     */
    public function __construct(
        string $projectId,
        string $locationId,
        string $keyRingId,
        string $keyId,
        string $versionId,
        ?KeyManagementServiceClient $client = null
    ) {
        $this->keyVersionName = KeyManagementServiceClient::cryptoKeyVersionName(
            $projectId,
            $locationId,
            $keyRingId,
            $keyId,
            $versionId
        );

        $this->kmsClient = $client ?? new KeyManagementServiceClient();
    }

    /**
     * @inheritDoc
     * @throws Exception
     * @throws ApiException
     */
    public function getDigest(): string
    {
        $algorithm = $this->ensurePublicKey()->getAlgorithm();
        return match ($algorithm) {
            CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_2048_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_3072_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_4096_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_2048_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_3072_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA256,
            CryptoKeyVersionAlgorithm::EC_SIGN_P256_SHA256 => Digest::SHA_256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_4096_SHA512,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512 => Digest::SHA_512,
            CryptoKeyVersionAlgorithm::EC_SIGN_P384_SHA384 => Digest::SHA_384,
            default => throw new Exception('Unknown algorithm id "%d".', $algorithm),
        };
    }

    /**
     * @inheritDoc
     * @throws Exception
     * @throws ApiException
     */
    public function getAlgorithm(): string
    {
        $algorithm = $this->ensurePublicKey()->getAlgorithm();
        return match ($algorithm) {
            CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_2048_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_3072_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_4096_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PKCS1_4096_SHA512 => Digest::RSA_ALGORITHM,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_2048_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_3072_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512 => Digest::RSA_PSS_ALGORITHM,
            CryptoKeyVersionAlgorithm::EC_SIGN_P256_SHA256,
            CryptoKeyVersionAlgorithm::EC_SIGN_P384_SHA384 => Digest::ECDSA_ALGORITHM,
            default => throw new Exception('Unknown algorithm id "%d".', $algorithm),
        };
    }

    /**
     * @inheritDoc
     * @see https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
     * @throws ApiException
     */
    public function getPssSaltLength(): int
    {
        // "For Probabilistic Signature Scheme (PSS), the salt length used is equal to the length of the digest
        // algorithm. For example, RSA_SIGN_PSS_2048_SHA256 will use PSS with a salt length of 256 bits."
        $algorithm = $this->ensurePublicKey()->getAlgorithm();
        return match ($algorithm) {
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_2048_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_3072_SHA256,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA256 => 256 / 8,
            CryptoKeyVersionAlgorithm::RSA_SIGN_PSS_4096_SHA512 => 512 / 8,
            default => throw new \BadMethodCallException('The algorithm does not support PSS padding.'),
        };
    }

    /**
     * Ensures that the public key and related information are loaded and returned.
     *
     * @return GcKmsPublicKey
     * @throws ApiException
     */
    protected function ensurePublicKey(): GcKmsPublicKey
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
    public function getPublicKey(): string
    {
        return $this->ensurePublicKey()->getPem();
    }

    /**
     * @inheritDoc
     * @throws ApiException|Exception
     */
    public function sign(string $data): string
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
