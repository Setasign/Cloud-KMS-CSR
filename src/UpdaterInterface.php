<?php

namespace setasign\CloudKmsCsr;

interface UpdaterInterface
{
    public function getDigest();

    public function getAlgorithm();

    public function getPssSaltLength();

    public function getPublicKey();

    public function sign($data);
}