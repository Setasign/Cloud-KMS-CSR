<?php

namespace setasign\CloudKmsCsr;

use SetaPDF_Signer_Asn1_Element as Asn1Element;

class Certificate extends \SetaPDF_Signer_X509_Certificate
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
     * @return Certificate
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public static function create(array $dn, $days = 365, $serial = 0, $configargs = [], array $extraattribs = null)
    {
        $privkey = openssl_pkey_new();
        if (!isset($configargs['config'])) {
            $configargs['config'] = __DIR__ . '/empty_openssl.cfg';
        }

        $csr = openssl_csr_new($dn, $privkey, $configargs, $extraattribs);
        openssl_csr_export($csr, $csrString);

        $certRespource = openssl_csr_sign($csr, null, $privkey, $days, $configargs, $serial);

        openssl_x509_export($certRespource, $certificateString);

        return new self($certificateString);
    }

    /**
     * Get the TBSCertificate value.
     *
     * @return Asn1Element
     */
    protected function getTBSCertificate()
    {
        return $this->_certificate->getChild(0);
    }

    /**
     * Get the data of the Subject Public Key Info field.
     *
     * @return string
     * @throws Exception
     */
    protected function getSubjectPublicKeyInfo()
    {
        $tbs = $this->getTBSCertificate();
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
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function update(UpdaterInterface $updater)
    {
        $this->updateSubjectPublicKeyInfo($updater);

        list(
            $signatureAlgorithmIdentifierAlgorithm,
            $signatureAlgorithmIdentifierParameter
        ) = $this->createSignatureAlgorithmIdentifier($updater);

        $tbs = $this->getTBSCertificate();
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
        // This is a BIT_STRING and not a OCTET_STRING as for "signedData"
        $signatureValue = $this->_certificate->getChild(2);
        $signatureValue->setValue("\x00" . $newSignatureValue);
    }
}
