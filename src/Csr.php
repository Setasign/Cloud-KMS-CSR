<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\CloudKmsCsr;

use SetaPDF_Signer_Pem as Pem;
use SetaPDF_Signer_X509_Format as Format;
use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Asn1_Oid as Oid;

class Csr
{
    use HelperTrait;

    /**
     * Flag to disable phpseclib usage during verification.
     *
     * @var bool
     */
    public static $usePhpseclibForRsaPss = true;

    /**
     * @var Asn1Element
     */
    protected $csr;

    /**
     * Creates a CSR instance by creating a brand new CSR with the use of OpenSSL functions.
     *
     * This method uses OpenSSL functions to creates dummy keys and creates a CSR.
     * It uses an empty openssl.cfg file if none is passed in the $configargs parameter.
     *
     * @see https://www.php.net/manual/de/function.openssl-csr-new
     * @param array $dn
     * @param array $configargs
     * @param array|null $extraattribs
     * @return Csr
     */
    public static function create(array $dn, array $configargs = [], ?array $extraattribs = null): Csr
    {
        $configargs = \array_merge(
            [
                'config' => __DIR__ . '/empty_openssl.cfg'
            ],
            $configargs
        );

        $privkey = null;
        $csr = \openssl_csr_new($dn, $privkey, $configargs, $extraattribs);
        \openssl_csr_export($csr, $csrString);

        return new self($csrString);
    }

    /**
     * Csr constructor.
     *
     * @param string $csr
     */
    public function __construct(string $csr)
    {
        if (\strpos($csr, '-----BEGIN CERTIFICATE REQUEST-----') === false) {
            if (($_csr = \base64_decode($csr, true)) !== false) {
                /** @noinspection CallableParameterUseCaseInTypeContextInspection */
                $csr = $_csr;
            }

            $csr = Pem::encode($csr, 'CERTIFICATE REQUEST');
        }

        $label = 'CERTIFICATE REQUEST';
        $csr = Pem::decode($csr, $label);

        try {
            $_csr = Asn1Element::parse($csr);
        } catch (\SetaPDF_Signer_Asn1_Exception $e) {
            throw new \InvalidArgumentException('CSR is not a valid ASN.1 structure.', 0, $e);
        }

        if ($_csr->getIdent() !== (Asn1Element::IS_CONSTRUCTED | Asn1Element::SEQUENCE)) {
            throw new \InvalidArgumentException('Invalid data type in CSR data structure (expected SEQUENCE).');
        }

        if ($_csr->getChildCount() !== 3) {
            throw new \InvalidArgumentException('Invalid element count in CSR data structure.');
        }

        $this->csr = $_csr;
    }

    /**
     * Get the CSR encoded as DER or PEM.
     *
     * @param string $format
     * @return string
     */
    public function get(string $format = Format::PEM): string
    {
        switch (\strtolower($format)) {
            case Format::DER:
                return (string) $this->csr;
            case Format::PEM:
                return Pem::encode((string)$this->csr, 'CERTIFICATE REQUEST');
            default:
                throw new \InvalidArgumentException(\sprintf('Unknown format "%s".', $format));
        }
    }

    /**
     * Get the signature algorithm and parameter.
     *
     * @return array The first value holds the OID of the algorithm. The second value is the ASN.1 structure of the
     *               parameters.
     */
    public function getSignatureAlgorithm(): array
    {
        $signatureAlgorithm = $this->csr->getChild(1);
        $parameter = $signatureAlgorithm->getChild(1);

        return [
            Oid::decode($signatureAlgorithm->getChild(0)->getValue()),
            $parameter === false ? null : clone $parameter
        ];
    }

    /**
     * Get the signature value.
     *
     * @param bool $hex
     * @return string
     */
    public function getSignatureValue(bool $hex = true): string
    {
        $signatureValue = $this->csr->getChild(2)->getValue();
        $signatureValue = \substr($signatureValue, 1);

        if ($hex) {
            return \SetaPDF_Core_Type_HexString::str2hex($signatureValue);
        }

        return $signatureValue;
    }

    /**
     * Get the signed data.
     *
     * @return string
     */
    public function getSignedData(): string
    {
        return (string)$this->csr->getChild(0);
    }

    /**
     * Get the data of the Subject Public Key Info field.
     *
     * @return Asn1Element
     * @throws Exception
     */
    protected function getSubjectPublicKeyInfo(): Asn1Element
    {
        $subjectPublicKeyInfo = $this->csr->getChild(0)->getChild(2);
        if (
            $subjectPublicKeyInfo->getIdent() !==
            (Asn1Element::IS_CONSTRUCTED | Asn1Element::SEQUENCE)
        ) {
            throw new Exception('Invalid subjectPKInfo structure in CSR.');
        }

        return $subjectPublicKeyInfo;
    }

    /**
     * Get the subject public key info algorithm identifier.
     *
     * @return array First entry is the OID of the identifier. The second entry are the raw parameters as ASN.1
     *               structures.
     * @throws Exception
     */
    public function getSubjectPublicKeyInfoAlgorithmIdentifier(): array
    {
        $subjectPublicKeyInfo = $this->getSubjectPublicKeyInfo();

        $algorithm = $subjectPublicKeyInfo->getChild(0);
        if ($algorithm->getIdent() !== (Asn1Element::IS_CONSTRUCTED | Asn1Element::SEQUENCE)) {
            throw new Exception('Invalid algorithm structure in CSR.');
        }

        $parameter = $algorithm->getChild(1);

        return [
            Oid::decode($algorithm->getChild(0)->getValue()),
            $parameter === false ? null : clone $parameter
        ];
    }

    /**
     * Update the CSR by the passed Updater instance.
     *
     * @param UpdaterInterface $updater
     * @throws Exception
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws \SetaPDF_Signer_Exception
     */
    public function update(UpdaterInterface $updater): void
    {
        $this->updateSubjectPublicKeyInfo($updater);

        [
            $signatureAlgorithmIdentifierAlgorithm,
            $signatureAlgorithmIdentifierParameter
        ] = $this->createSignatureAlgorithmIdentifier($updater);

        $signatureAlgorithmIdentifier = $this->csr->getChild(1);
        while ($signatureAlgorithmIdentifier->getChildCount() > 0) {
            $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(0));
        }

        $signatureAlgorithmIdentifier->addChild($signatureAlgorithmIdentifierAlgorithm);
        $signatureAlgorithmIdentifier->addChild($signatureAlgorithmIdentifierParameter);

        $newSignatureValue = $updater->sign($this->getSignedData());
        $signatureValue = $this->csr->getChild(2);
        $signatureValue->setValue("\x00" . $newSignatureValue);
    }

    /**
     * Verify the CSR.
     *
     * @return bool
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws Exception
     */
    public function verify(): bool
    {
        $signedData = $this->getSignedData();
        $publicKey = Pem::encode($this->getSubjectPublicKeyInfo(), 'PUBLIC KEY');

        $signatureAlgorithm = $this->getSignatureAlgorithm();
        $algorithm = false;

        if ($signatureAlgorithm[0] === '1.2.840.113549.1.1.10') {
            /* RSASSA-PSS-params  ::=  SEQUENCE  {
             *    hashAlgorithm      [0] HashAlgorithm DEFAULT
             *                             sha1Identifier,
             *    maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT
             *                             mgf1SHA1Identifier,
             *    saltLength         [2] INTEGER DEFAULT 20,
             *    trailerField       [3] INTEGER DEFAULT 1  }
             */
            $parameters = [
                0 => Digest::SHA_1,
                1 => Digest::SHA_1,
                2 => null, // will be resolved automatically by phpseclib or extracted
                3 => 1
            ];
            /** @var Asn1Element $parameter */
            /** @var Asn1Element[] $signatureAlgorithm */
            foreach ($signatureAlgorithm[1]->getChildren() as $parameter) {
                $key = \ord(
                    $parameter->getIdent() ^ (
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC |
                        Asn1Element::IS_CONSTRUCTED
                    )
                );

                switch ($key) {
                    case 0:
                        $algorithmOid = Oid::decode($parameter->getChild(0)->getChild(0)->getValue());
                        $parameters[0] = Digest::getByOid($algorithmOid);
                        break;
                    case 1:
                        $maskGen = $parameter->getChild(0);
                        $maskGenOid = Oid::decode($maskGen->getChild(0)->getValue());
                        if ($maskGenOid !== '1.2.840.113549.1.1.8') {
                            throw new Exception(
                                \sprintf('Unsupported mask generation function (%s).', $maskGenOid)
                            );
                        }

                        $algorithmOid = Oid::decode($maskGen->getChild(1)->getChild(0)->getValue());
                        $parameters[1] = Digest::getByOid($algorithmOid);
                        break;
                    case 2:
                        $value = $parameter->getChild(0)->getValue();
                        $parameters[2] = \SetaPDF_Core_BitConverter::formatFromInt($value, \strlen($value));
                        break;
                }
            }

            if (self::$usePhpseclibForRsaPss && \class_exists(\phpseclib\Crypt\RSA::class)) {
                $rsa = new \phpseclib\Crypt\RSA();

                // PHPSecLib doesn't support a complete key, if the algorithm is set to rsaPSS.
                // until this is merged and released: https://github.com/phpseclib/phpseclib/pull/1584
                // We simply change these fields to standard rsaEncryption.
                // Another way could be to use the raw key from "subjectPublicKey".
                $_publicKey = Asn1Element::parse((string)$this->getSubjectPublicKeyInfo());
                $_publicKey->getChild(0)->getChild(0)->setValue(Oid::encode('1.2.840.113549.1.1.1'));
                $_publicKey->getChild(0)->addChild(new Asn1Element(Asn1Element::NULL));
                $_publicKey = Pem::encode($_publicKey, 'PUBLIC KEY');

                $rsa->loadKey($_publicKey);

                $rsa->setHash($parameters[0]);
                $rsa->setMGFHash($parameters[1]);
                if ($parameters[2] !== null) {
                    $rsa->setSaltLength($parameters[2]);
                }

                return $rsa->verify(
                    $signedData,
                    $this->getSignatureValue(false)
                );
            }

            $algorithm = $parameters[0];
        }

        if ($algorithm === false) {
            $algorithm = \array_search(
                $signatureAlgorithm[0],
                Digest::$encryptionOids[Digest::DSA_ALGORITHM],
                true
            );
        }

        if ($algorithm === false) {
            $algorithm = \array_search(
                $signatureAlgorithm[0],
                Digest::$encryptionOids[Digest::ECDSA_ALGORITHM],
                true
            );
        }

        if ($algorithm !== false) {
            $result = \openssl_verify(
                $signedData,
                $this->getSignatureValue(false),
                $publicKey,
                $algorithm
            );

            return ($result === 1);
        }

        $algorithm = \in_array(
            $signatureAlgorithm[0],
            Digest::$encryptionOids[Digest::RSA_ALGORITHM],
            true
        );

        // These are all "rsa" signature algorithms
        if ($algorithm === false && $signatureAlgorithm[0] !== '1.2.840.113549.1.1.1') {
            throw new Exception(\sprintf('Unsupported signature algorithm "%s".', $signatureAlgorithm[0]));
        }

        if (\openssl_public_decrypt($this->getSignatureValue(false), $result, $publicKey)) {
            $decryptedResult = Asn1Element::parse($result);

            if ($decryptedResult->getChildCount() < 2) {
                return false;
            }

            $decryptedDigestAlgorithm = $decryptedResult->getChild(0);
            if (
                !$decryptedDigestAlgorithm
                || $decryptedDigestAlgorithm->getIdent() !== (Asn1Element::IS_CONSTRUCTED | Asn1Element::SEQUENCE)
                || $decryptedDigestAlgorithm->getChildCount() < 1
            ) {
                return false;
            }

            $decryptedDigestAlgorithm = $decryptedDigestAlgorithm->getChild(0)->getValue();

            $hashOid = Oid::decode($decryptedDigestAlgorithm);

            $digestAlgorithm = Digest::getByOid($hashOid);
            if (!$digestAlgorithm) {
                throw new Exception(\sprintf('Unsupported digest algorithm "%s".', $hashOid));
            }

            $decryptedDigest = $decryptedResult->getChild(1)->getValue();
            $digest = \hash($digestAlgorithm, $signedData, true);

            return ($decryptedDigest === $digest);
        }

        return false;
    }
}
