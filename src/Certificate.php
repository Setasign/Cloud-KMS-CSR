<?php

/**
 * @copyright Copyright (c) 2026 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\CloudKmsCsr;

use setasign\SetaPDF2\Signer\Asn1\Element as Asn1Element;
use setasign\SetaPDF2\Signer\Asn1\Exception;

class Certificate extends \setasign\SetaPDF2\Signer\X509\Certificate
{
    use HelperTrait;

    /**
     * Creates a self-signed certificate instance by using OpenSSL functions.
     *
     * This method uses OpenSSL functions to creates dummy keys and the certificate.
     * It uses an empty openssl.cfg file if none is passed in the $configargs parameter.
     *
     * @see https://www.php.net/manual/de/function.openssl-csr-new
     * @param array $dn
     * @param int $days
     * @param int $serial
     * @param array $configargs
     * @param array|null $extraattribs
     * @return self
     * @throws Exception
     */
    public static function create(
        array $dn,
        int   $days = 365,
        int   $serial = 0,
        array $configargs = [],
        ?array $extraattribs = null
    ): self
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

        $certRespource = \openssl_csr_sign($csr, null, $privkey, $days, $configargs, $serial);

        \openssl_x509_export($certRespource, $certificateString);

        return new self($certificateString);
    }

    /**
     * Get the data of the Subject Public Key Info field.
     *
     * @return Asn1Element
     * @throws Exception
     */
    protected function getSubjectPublicKeyInfo(): Asn1Element
    {
        $tbs = $this->_getTBSCertificate();
        $offset = 5;

        if ($tbs->getChild(0)->getIdent() !== Asn1Element::INTEGER) {
            $offset++;
        }

        $subjectPublicKeyInfo = $tbs->getChild($offset);
        if ($subjectPublicKeyInfo->getIdent() !== (Asn1Element::IS_CONSTRUCTED | Asn1Element::SEQUENCE)) {
            throw new Exception('Invalid subjectPublicKeyInfo structure in X509 certificate.');
        }

        return $subjectPublicKeyInfo;
    }

    /**
     * Update the certificate by the passed Updater instance.
     *
     * @param UpdaterInterface $updater
     * @throws Exception
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws \setasign\SetaPDF2\Signer\Exception
     */
    public function update(UpdaterInterface $updater): void
    {
        $this->updateSubjectPublicKeyInfo($updater);

        [
            $signatureAlgorithmIdentifierAlgorithm,
            $signatureAlgorithmIdentifierParameter
        ] = $this->createSignatureAlgorithmIdentifier($updater);

        $tbs = $this->_getTBSCertificate();
        $offset = 1;

        if ($tbs->getChild(0)->getIdent() !== Asn1Element::INTEGER) {
            $offset++;
        }

        $signatureAlgorithm = $tbs->getChild($offset);
        while ($signatureAlgorithm->getChildCount() > 0) {
            $signatureAlgorithm->removeChild($signatureAlgorithm->getChild(0));
        }

        $signatureAlgorithm->addChild($signatureAlgorithmIdentifierAlgorithm);
        $signatureAlgorithm->addChild($signatureAlgorithmIdentifierParameter);

        // now the identifier
        $signatureAlgorithmIdentifier = $this->_certificate->getChild(1);

        while ($signatureAlgorithmIdentifier->getChildCount() > 0) {
            $signatureAlgorithmIdentifier->removeChild($signatureAlgorithmIdentifier->getChild(0));
        }

        $signatureAlgorithmIdentifier->addChild($signatureAlgorithmIdentifierAlgorithm);
        $signatureAlgorithmIdentifier->addChild($signatureAlgorithmIdentifierParameter);

        $newSignatureValue = $updater->sign($this->getSignedData());
        // This is a BIT_STRING and not an OCTET_STRING as for "signedData"
        $signatureValue = $this->_certificate->getChild(2);
        $signatureValue->setValue("\x00" . $newSignatureValue);
    }
}
