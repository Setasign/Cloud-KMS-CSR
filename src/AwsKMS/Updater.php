<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\CloudKmsCsr\AwsKMS;

use Aws\Kms\KmsClient;
use setasign\CloudKmsCsr\Exception;
use setasign\CloudKmsCsr\UpdaterInterface;
use setasign\SetaPDF2\Signer\Digest;
use setasign\SetaPDF2\Signer\PemHelper;

class Updater implements UpdaterInterface
{
    protected KmsClient $kmsClient;
    protected string $keyId;
    protected ?string $signatureAlgorithm;
    protected ?\Aws\Result $publicKey = null;

    /**
     * @param string $keyId
     * @param KmsClient $kmsClient
     */
    public function __construct(string $keyId, KmsClient $kmsClient)
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
    public function setSignatureAlgorithm(string $signatureAlgorithm): void
    {
        $publicKey = $this->ensurePublicKey();
        if (!\in_array($signatureAlgorithm, $publicKey->get('SigningAlgorithms'), true)) {
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
    public function getSignatureAlgorithm(): string
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
    public function getDigest(): string
    {
        $algorithm = $this->getSignatureAlgorithm();
        return match ($algorithm) {
            'RSASSA_PKCS1_V1_5_SHA_256', 'RSASSA_PSS_SHA_256', 'ECDSA_SHA_256' => Digest::SHA_256,
            'RSASSA_PKCS1_V1_5_SHA_384', 'RSASSA_PSS_SHA_384', 'ECDSA_SHA_384' => Digest::SHA_384,
            'RSASSA_PKCS1_V1_5_SHA_512', 'RSASSA_PSS_SHA_512', 'ECDSA_SHA_512' => Digest::SHA_512,
            default => throw new Exception('Unknown algorithm "%s".', $algorithm),
        };
    }

    /**
     * @inheritDoc
     * @throws Exception
     */
    public function getAlgorithm(): string
    {
        $algorithm = $this->getSignatureAlgorithm();
        return match ($algorithm) {
            'RSASSA_PKCS1_V1_5_SHA_256',
            'RSASSA_PKCS1_V1_5_SHA_384',
            'RSASSA_PKCS1_V1_5_SHA_512' => Digest::RSA_ALGORITHM,
            'RSASSA_PSS_SHA_256',
            'RSASSA_PSS_SHA_384',
            'RSASSA_PSS_SHA_512' => Digest::RSA_PSS_ALGORITHM,
            'ECDSA_SHA_256',
            'ECDSA_SHA_384',
            'ECDSA_SHA_512' => Digest::ECDSA_ALGORITHM,
            default => throw new Exception('Unknown algorithm "%s".', $algorithm),
        };
    }

    /**
     * @inheritDoc
     * @see https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose.html
     */
    public function getPssSaltLength(): int
    {
        // E.g.: "PKCS #1 v2.2, Section 8.1, RSA signature with PSS padding using SHA-256 for both the message
        // digest and the MGF1 mask generation function along with a 256-bit salt"
        $algorithm = $this->getSignatureAlgorithm();
        return match ($algorithm) {
            'RSASSA_PSS_SHA_256' => 256 / 8,
            'RSASSA_PSS_SHA_384' => 384 / 8,
            'RSASSA_PSS_SHA_512' => 512 / 8,
            default => throw new \BadMethodCallException('The key does not support PSS padding.'),
        };
    }

    /**
     * Ensures that the public key and related information are loaded and returned.
     *
     * @return \Aws\Result
     */
    public function ensurePublicKey(): \Aws\Result
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
    public function getPublicKey(): string
    {
        return PemHelper::encode($this->ensurePublicKey()->get('PublicKey'), 'PUBLIC KEY');
    }

    /**
     * @inheritDoc
     * @throws Exception
     */
    public function sign(string $data): string
    {
        $result = $this->kmsClient->sign([
            'KeyId' => $this->keyId,
            'Message' => \hash($this->getDigest(), $data, true),
            'MessageType' => 'DIGEST',
            'SigningAlgorithm' => $this->getSignatureAlgorithm()
        ]);

        return $result->get('Signature');
    }
}
