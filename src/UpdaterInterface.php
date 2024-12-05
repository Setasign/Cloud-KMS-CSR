<?php

/**
 * @copyright Copyright (c) 2021 Setasign GmbH & Co. KG (https://www.setasign.com)
 * @license   http://opensource.org/licenses/mit-license The MIT License
 */

namespace setasign\CloudKmsCsr;

interface UpdaterInterface
{
    /**
     * Get the digest method.
     *
     * @return string Possible values are the constants from \SetaPDF_Signer_Digest::SHA_*.
     */
    public function getDigest(): string;

    /**
     * Get the signature algorithm.
     *
     * @return string Possible values are the constants from \SetaPDF_Signer_Digest::*_ALGORITHM
     */
    public function getAlgorithm(): string;

    /**
     * Get the salt length if PSS padding is used.
     *
     * @return int The length in bytes
     */
    public function getPssSaltLength(): int;

    /**
     * Get the public key PEM encoded.
     *
     * @return string
     */
    public function getPublicKey(): string;

    /**
     * Signs the given data.
     *
     * @param string $data
     * @return string
     */
    public function sign(string $data): string;
}