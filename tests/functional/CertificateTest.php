<?php

namespace setasign\CloudKmsCsr\tests\functional;

use PHPUnit\Framework\TestCase;
use setasign\CloudKmsCsr\Certificate;

class CertificateTest extends TestCase
{
    /**
     * @return void
     * @throws \setasign\SetaPDF2\Signer\Asn1\Exception
     * @throws \setasign\SetaPDF2\Signer\Exception
     */
    public function testCreate(): void
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
