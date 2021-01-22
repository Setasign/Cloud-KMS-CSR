<?php

namespace setasign\CloudKmsCsr\tests\functional;

use PHPUnit\Framework\TestCase;
use setasign\CloudKmsCsr\Csr;
use setasign\CloudKmsCsr\Exception;

class CsrTest extends TestCase
{
    /**
     * @return array
     * @throws \SetaPDF_Signer_Asn1_Exception
     */
    public function verifyDataProvider()
    {
        return [
            // rsassaPss, 2048 bits, sha-256
            [
                '-----BEGIN CERTIFICATE REQUEST-----
MIIC/zCCAbMCAQAwgYcxCzAJBgNVBAYTAkRFMRYwFAYDVQQIDA1OaWVkZXJzYWNo
c2VuMR8wHQYDVQQKDBZTZXRhc2lnbiBHbWJIICYgQ28uIEtHMRQwEgYDVQQDDAtE
ZXYuICYgVGVzdDEpMCcGCSqGSIb3DQEJARYac2V0YXBkZi1kZW1vc0BzZXRhc2ln
bi5jb20wggEgMAsGCSqGSIb3DQEBCgOCAQ8AMIIBCgKCAQEAmPgoJ0ZfKyKQYqHY
KB1iFUJkoDgLHl90gXvh++dOcUsu9/WRTBrV4Hy8Kn9IXp6risbdtIOPdSBd558R
lozMhEuilofRhg3TeRcZyRUPaHhusOf9KRJuIkCewJRE91OqKvz/0foTv5acaoM5
zr5tOFJhv/fU7jWz/YnyB1V91uNvEmJZUHMThtvte3V6gL4PL0Rtbv+VVZPPtQW/
zYqEJmbb21U3qNT+6Qi9Tz1vRpJrjYI12G/8WzqX+6K2ePhFUYPIgWY6gZ9Pc3zk
xeMAuLOvuaCBUq16WNv1d97vNfNgPx1mPy6eb7CQvvYbc9ZoPvSdz5zFUvs0f5VV
mPTP/QIDAQABoAAwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoG
CSqGSIb3DQEBCDANBglghkgBZQMEAgEFAKIDAgEgA4IBAQAGEwDq7y/qfRVQPNI+
wTrTe7yP1jOjRdYDIHHLYIlTV2Q6ufNoqxKCnwT5ghLYhWT7BNfixyLuqfRHrPuJ
EUjycMVpVrZUBiy8u6FF2TquVMpN0TZLkfaIgwCbqohbW+Z0Qg+Wt5YbBAVUeLms
bInTKY3+FTrO4V0px1A6f7w5UTUiI8iYAcMkpg6USyySCIZrJHKBBwYvCTIhhyz2
8GavnE8CQfmBOo/17C7SmMR+5n84kBm3pGd8cBBo0JjyXsJ2OaQFj+2F/vM9Th6c
o4hni16A8Gg+jy9LuOb1u+B7RynjTAjtPtOQ0eOaGTNBKt0aWfCAXuLOo6yfT3Te
lQ5l
-----END CERTIFICATE REQUEST-----'
            ],
            // rsassaPss, 2048 bits, sha-256
            [
                '-----BEGIN CERTIFICATE REQUEST-----
MIICjTCCAUQCAQAwGTEXMBUGA1UEAwwOcmFuY2hlci5teS5vcmcwggEgMAsGCSqG
SIb3DQEBCgOCAQ8AMIIBCgKCAQEA0c89/m2NOYQe1C/OLr6si2Mbc5S+Ho2KFz1t
dK7TE0WOX/1N3Ihey1FQb8uHTuKweBkUR9efimab+JkhCHT0AKBOMRq7yulwsHQF
L10OBOHyG+CRt3FZHZQ/GTfhsVx2AimVySyUB8Hj795sv45u9RpbexmixOrcPr+q
HR+6MZmD8Qoslw0IcjbtcyIBPnJbO1KMdbBCbssHAnm4qUUsQMJn/4shX+88Qgx8
TqUD/46csrBUUHnjR5dA+5ZqvUBEdc3w+mIKokdqd11gwDmX8LDlHuQn4IGgfNo9
49eMH1XVt/MQHMEdvZ12JKO6b6q0ta4fRDsHyA9f0SPEjC4LMwIDAQABoAAwPgYJ
KoZIhvcNAQEKMDGgDTALBglghkgBZQMEAgGhGjAYBgkqhkiG9w0BAQgwCwYJYIZI
AWUDBAIBogQCAgDeA4IBAQAWnzHbV1IBp10zM69aV1vJAK3OR7LcvZ4xH++1S1pZ
r4C4ttncXZonXq8CBhRUrfRzzErBGSGjtIiItPki9tUPo/USDCLmOEKbNuClAnDp
xn9SHTGknFkMlZxdfl1P3V7RpELU8Z0EndDuz5aLKSQ6xurNdLvs/SiF5epCyxXq
8YdoUQ5ngVbONHgXzMw4Et8KPwAjKEHxPXHwpzzzr4A9Y0v7I4fFzF/1+ZTq89B3
Thi5hwspSZXCfxYaIzvVk7qNOEzd2VEuo+kpnYYMHed0xj/XJ+X9EfG+i7cKNDBH
xKp4l3VtLKoM3VH68KRM82omnap4qPoztdGIrq1kYL6c
-----END CERTIFICATE REQUEST-----'
            ],
            // sha256WithRSAEncryption, 4096 bits, sha-256
            [
                '-----BEGIN CERTIFICATE REQUEST-----
MIIE5jCCAs4CAQAwdTEZMBcGA1UEAxMQRGVtby1FbnZpcm9ubWVudDEfMB0GA1UECgwWU2V0YXNpZ24gR21iSCAmIENvLiBLRzESMBAGA1UEBxMJSGVsbXN0ZWR0MRYwFAYDVQQIEw1OaWVkZXJzYWNoc2VuMQswCQYDVQQGEwJERTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOSQLOPD/cSCLRVxuL39JiVvjgQVVcpMH+cmhsRiXQ5a8C/+jxDO4iOX+cFqxVL8cwyo+wH3t5FJgwruXkyYHPOUbtdbN9ZHFLzZgMj5ZmAOmp6cMdGxto/b+orvV9yIm78GCYqxpijQLmiG9r1ksFrhTHocpSNu+TYsqYTO4HpgB1oJK06KuKTwZaHHU0+yOIJQUjogAfKG5fHOLwQpr/88mwGYyDIqlgjgyzdAaNRKPz1TmMoOdGfywJkqy8NccjVIOMyUxAClrwSAxfb/dTzJOSVib2+NAHqgV1ZgMSWyAIkTpkIy8HN39wnENODxex+xI+iOfahMDZHR1vCE/T45l8GNcrxqr016w3ITf+PKK9HQlkwevM6tJhVSHg6GVTtAWyKytP6zGsmZzxbEUFAohHQA0azN4PCPB7Ll0HDww2+rtNVF89SYg/wnR50RmlAhX/XhBsizGX+7/7I4UJLaWBrCr8jYiHTS2Q2lhOjjUmSla5qGojDSsmDNNPTKXuPqvAUrqALJBRRYyFB5Td6JnnD3DTGCK2lrPoUu+xcRHXjrWiLFy/TfVIEtm8sJn5Jax1aXGBD0K3/8N36yPilXr4Y4/bkICWBUydNmu3aOqREzLbuUka0eslTo1VMg76WoxvA6VFiTx3hOVpo0xhMBL3sqFOFC6Zv4aZHXbkhHAgMBAAGgLDAqBgkqhkiG9w0BCQ4xHTAbMA4GA1UdDwEB/wQEAwIHgDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQDbQs27MgBSB0K4V9auErJF5phBug7EXaz5OBksSdPNkHuuIF6I1YPmFM4C21A8ctyWOxPwkmrCNwC/reUt9zkekRNaQaPmD+qq6ct8oMoTy96fzjHJfL+KtkzpfQlAveD3Egkxajl/OUA7C7r0KPMeeCTyo7iLOWIZWTsTqo24CmBTRqIWUEh0YvalTPZdozjRWF5ASYRporKRcdUixnJZYUTCDYsH5O1whuJWFBXj4JAq2zjwgu4rT96upx5x3nwBDnoYItfkV4vIPH+O7YqdAJMao9pjSsIct7kh1bHU2pqmNxuJvlOOuNGxrGP6xx+LcPS4/cemc1AmPCWeg+akNd5EbMXcox+xhnZ8VG9rXrnnaZXkgG+bZxlJcfS7BT+BBj65491pps+lyoOxj4vhjddwv3hyMi2kojl5F7Ao7jEnbxRl6kaWI3DEOGWvH7JbopJ7UOhbqRnFTJO/B8+NfUEvKdfO9K9D795wgIQHrBrOCan/ZsCCivHtE7QeYt0rnWjTSBc2hizM5xbRb8ZG8LawD4EWRexbT1I+UXCQxnZio6oTSeV0y7sJ+q6fusHW7rs7TaBKgjxzJJDhpjR15j8JwhZLAZZtobnd8ehttihQ2haD3h5/F3xa2wRXvSzDlQUWAVjdmdLJtGr/TsLCnN/thVlZ5oXUBRND4/nH/Q==
-----END CERTIFICATE REQUEST-----'
            ],
            // created
            [
                Csr::create(['commonName' => 'Tester'])->get()
            ]
        ];
    }

    /**
     * @param $csrString
     * @throws \SetaPDF_Signer_Asn1_Exception
     * @throws Exception
     * @dataProvider verifyDataProvider
     */
    public function testVerify($csrString)
    {
        $csr = new Csr($csrString);
        $this->assertTrue($csr->verify());
    }
}
