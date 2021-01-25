<?php

namespace setasign\CloudKmsCsr\tests\functional;

use PHPUnit\Framework\TestCase;
use setasign\CloudKmsCsr\Certificate;

class CertificateTest extends TestCase
{
    /**
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws \SetaPDF_Signer_Exception
     */
    public function testCreate()
    {
        $certificate = Certificate::create([
            'commonName' => 'Developer',
            'organizationName' => 'Setasign GmbH & Co. KG'
        ]);

        $this->assertTrue($certificate->verify());

        $subject = $certificate->getSubjectName();
        $this->assertSame('/CN=Developer/O=Setasign GmbH & Co. KG', $subject);
    }
}
