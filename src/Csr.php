<?php

namespace setasign\CloudKmsCsr;

use \SetaPDF_Signer_Pem as Pem;
use \SetaPDF_Signer_X509_Format as Format;
use \SetaPDF_Signer_Asn1_Element as Asn1Element;
use \SetaPDF_Signer_Digest as Digest;
use \SetaPDF_Signer_Asn1_Oid as Oid;

class Csr
{
    public static $usePhpseclibForRsaPss = true;

    protected $_csr;

    public static function create(array $dn, $configargs = [], array $extraattribs = null)
    {
        $privkey = openssl_pkey_new();
        if (!isset($configargs['config'])) {
            $configargs['config'] = __DIR__ . '/empty_openssl.cfg';
        }

        $csr = openssl_csr_new($dn, $privkey, $configargs,  $extraattribs);
        openssl_csr_export($csr, $csrString);

        return new self($csrString);
    }

    public function __construct($csr)
    {
        if (\strpos($csr, '-----BEGIN CERTIFICATE REQUEST-----') === false) {
            if (($_csr = \base64_decode($csr, true)) !== false) {
                $csr = $_csr;
            }

            $csr = Pem::encode($csr, 'CERTIFICATE REQUEST');
        }

        $label = 'CERTIFICATE REQUEST';
        $csr = Pem::decode($csr, $label);
        $this->_csr = Asn1Element::parse($csr);

        // TODO: Validate some elements
    }

    public function get($format = Format::PEM)
    {
        switch (strtolower($format)) {
            case Format::DER:
                return (string) $this->_csr;
            case Format::PEM:
                return Pem::encode((string)$this->_csr, 'CERTIFICATE REQUEST');
            default:
                throw new \InvalidArgumentException(\sprintf('Unknown format "%s".', $format));
        }
    }

    public function getSignatureAlgorithm()
    {
        $signatureAlgorithm = $this->_csr->getChild(1);
        $parameter = $signatureAlgorithm->getChild(1);

        return [
            Oid::decode($signatureAlgorithm->getChild(0)->getValue()),
            $parameter === false ? null : clone $parameter
        ];
    }

    public function getSignatureValue($hex = true)
    {
        $signatureValue = $this->_csr->getChild(2)->getValue();
        $signatureValue = \substr($signatureValue, 1);

        if ($hex) {
            return \SetaPDF_Core_Type_HexString::str2hex($signatureValue);
        }

        return $signatureValue;
    }

    public function getSignedData()
    {
        return (string)$this->_csr->getChild(0);
    }

    /**
     * Get the data of the Subject Public Key Info field.
     *
     * @return string
     * @throws Exception
     */
    public function getSubjectPublicKeyInfo()
    {
        $subjectPublicKeyInfo = $this->_csr->getChild(0)->getChild(2);
        if (
            $subjectPublicKeyInfo->getIdent() !==
            (Asn1Element::IS_CONSTRUCTED | Asn1Element::SEQUENCE)
        ) {
            throw new Exception('Invalid subjectPKInfo structure in CSR.');
        }

        return $subjectPublicKeyInfo;
    }

    public function getSubjectPublicKeyInfoAlgorithmIdentifier()
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

    public function update(UpdaterInterface $updater)
    {
        $digest = $updater->getDigest();
        $algorithm = $updater->getAlgorithm();

        // get the public key
        $publicKey = Asn1Element::parse(Pem::decode($updater->getPublicKey()));
        // and update the subject public key with it
        $subjectPublicKeyInfo = $this->getSubjectPublicKeyInfo();
        $subjectPublicKeyInfo->removeChild($subjectPublicKeyInfo->getChild(0));
        $subjectPublicKeyInfo->setChildren($publicKey->getChildren());

        $pubKeyInfoAlgorithmIdentifier = $this->getSubjectPublicKeyInfoAlgorithmIdentifier();

        if ($algorithm === Digest::RSA_PSS_ALGORITHM) {
            $saltLength = $updater->getPssSaltLength();

            $signatureAlgorithmIdentifierAlgorithm = new Asn1Element(
                Asn1Element::OBJECT_IDENTIFIER,
                Oid::encode('1.2.840.113549.1.1.10')
            );
            $signatureAlgorithmIdentifierParameter = new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED, '',
                [
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED, '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED, '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Oid::encode(Digest::getOid($digest))
                                    ),
                                    new Asn1Element(Asn1Element::NULL)
                                ]
                            )
                        ]
                    ),
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x01", '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED, '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Oid::encode('1.2.840.113549.1.1.8')
                                    ),
                                    new Asn1Element(
                                        Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED, '',
                                        [
                                            new Asn1Element(
                                                Asn1Element::OBJECT_IDENTIFIER,
                                                Oid::encode(Digest::getOid($digest))
                                            ),
                                            new Asn1Element(Asn1Element::NULL)
                                        ]
                                    )
                                ]
                            )
                        ]
                    ),
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x02", '',
                        [
                            new Asn1Element(Asn1Element::INTEGER, \chr($saltLength))
                        ]
                    )
                ]
            );
        } else {
            $signatureAlgorithmIdentifierAlgorithm = new Asn1Element(
                Asn1Element::OBJECT_IDENTIFIER,
                Oid::encode(Digest::getOid($digest, $pubKeyInfoAlgorithmIdentifier[0]))
            );

            $signatureAlgorithmIdentifierParameter = $pubKeyInfoAlgorithmIdentifier[1];
        }

        $signatureAlgorithmIdentifier = $this->_csr->getChild(1);
        while ($signatureAlgorithmIdentifier->getChildCount() > 0) {
            $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(0));
        }

        $signatureAlgorithmIdentifier->addChild($signatureAlgorithmIdentifierAlgorithm);
        $signatureAlgorithmIdentifier->addChild($signatureAlgorithmIdentifierParameter);

        $newSignatureValue = $updater->sign($this->getSignedData());
        $signatureValue = $this->_csr->getChild(2);
        $signatureValue->setValue("\x00" . $newSignatureValue);
    }

    /**
     * Verify the signed object.
     *
     * @return bool
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws Exception
     */
    public function verify()
    {
        $signedData = $this->getSignedData();
        if ($signedData === false) {
            return false;
        }

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

        $algorithm = \array_search(
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
            if (!$decryptedDigestAlgorithm || $decryptedDigestAlgorithm->getIdent() !==
                (Asn1Element::IS_CONSTRUCTED | Asn1Element::SEQUENCE) ||
                $decryptedDigestAlgorithm->getChildCount() < 1
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