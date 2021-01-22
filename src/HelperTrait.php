<?php

namespace setasign\CloudKmsCsr;

use SetaPDF_Signer_Asn1_Element as Asn1Element;
use SetaPDF_Signer_Digest as Digest;
use SetaPDF_Signer_Asn1_Oid as Oid;
use SetaPDF_Signer_Pem as Pem;

trait HelperTrait
{
    /**
     * Updates the SubjectPublicKeyInfo with the public key of the Updater instance.
     *
     * @param UpdaterInterface $updater
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    protected function updateSubjectPublicKeyInfo(UpdaterInterface $updater)
    {
        // get the public key
        $publicKey = Asn1Element::parse(Pem::decode($updater->getPublicKey()));
        // and update the subject public key with it
        $subjectPublicKeyInfo = $this->getSubjectPublicKeyInfo();
        $subjectPublicKeyInfo->removeChild($subjectPublicKeyInfo->getChild(0));
        $subjectPublicKeyInfo->setChildren($publicKey->getChildren());
    }

    /**
     * Creates the SignatureAlgorithmIdentifier structures by the information resolved from the Updater instance.
     *
     * @param UpdaterInterface $updater
     * @return array
     */
    protected function createSignatureAlgorithmIdentifier(UpdaterInterface $updater)
    {
        $digest = $updater->getDigest();

        if ($updater->getAlgorithm() === Digest::RSA_PSS_ALGORITHM) {
            $saltLength = $updater->getPssSaltLength();

            $signatureAlgorithmIdentifierAlgorithm = new Asn1Element(
                Asn1Element::OBJECT_IDENTIFIER,
                Oid::encode('1.2.840.113549.1.1.10')
            );
            $signatureAlgorithmIdentifierParameter = new Asn1Element(
                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                '',
                [
                    new Asn1Element(
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED,
                        '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                '',
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
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x01",
                        '',
                        [
                            new Asn1Element(
                                Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                '',
                                [
                                    new Asn1Element(
                                        Asn1Element::OBJECT_IDENTIFIER,
                                        Oid::encode('1.2.840.113549.1.1.8')
                                    ),
                                    new Asn1Element(
                                        Asn1Element::SEQUENCE | Asn1Element::IS_CONSTRUCTED,
                                        '',
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
                        Asn1Element::TAG_CLASS_CONTEXT_SPECIFIC | Asn1Element::IS_CONSTRUCTED | "\x02",
                        '',
                        [
                            new Asn1Element(Asn1Element::INTEGER, \chr($saltLength))
                        ]
                    )
                ]
            );
        } else {
            $pubKeyInfoAlgorithmIdentifier = $this->getSubjectPublicKeyInfoAlgorithmIdentifier();
            $signatureAlgorithmIdentifierAlgorithm = new Asn1Element(
                Asn1Element::OBJECT_IDENTIFIER,
                Oid::encode(Digest::getOid($digest, $pubKeyInfoAlgorithmIdentifier[0]))
            );

            $signatureAlgorithmIdentifierParameter = clone $pubKeyInfoAlgorithmIdentifier[1];
        }

        return [$signatureAlgorithmIdentifierAlgorithm, $signatureAlgorithmIdentifierParameter];
    }
}
