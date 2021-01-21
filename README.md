# Certificate signing request and self-signed certificate generator/updater for cloud Key Management Systems

This project offers some PHP classes to use keys stored in 
[Amazon KMS](https://aws.amazon.com/kms/) or 
[Google Cloud KMS](https://cloud.google.com/security-key-management) to create
certificate signing request (CSRs) and self-signed certificates (for testing purpose).

It is based on functionalities of the [SetaPDF-Signer](https://www.setasign.com/signer)
component. The [SetaPDF-Signer](https://www.setasign.com/signer) component is a digital
signature solution for PDF documents in pure PHP.

Both AWS KMS and Google Cloud KMS allow you to store your keys on hardware security
modules (HSMs). By doing this you can request certificates from certificate
authorities 
which validate through the
[Adobe Approved Trust List](https://helpx.adobe.com/acrobat/kb/approved-trust-list2.html)
(AATL).

The resulting certificates can then be used with the modules for the
[SetaPDF-Signer](https://www.setasign.com/signer) component:

- Module for [Amazon AWS KMS](https://github.com/Setasign/SetaPDF-Signer-Addon-AWS-KMS)
- Module for [Google Cloud KMS](https://github.com/Setasign/SetaPDF-Signer-Addon-Google-Cloud-KMS)

## Installation

Add following to your composer.json:

```json
{
    "require": {
        "setasign/cloud-kms-csr": "^1.0"
    },
    "repositories": [
        {
            "type": "composer",
            "url": "https://www.setasign.com/downloads/"
        }
    ]
}
```

and execute `composer update`. You need to define the `repository` to evaluate the dependency to the
[SetaPDF-Signer](https://www.setasign.com/signer) component
(see [here](https://getcomposer.org/doc/faqs/why-can%27t-composer-load-repositories-recursively.md)
for more details).

The Setasign repository requires authentication data: You can use your credentials
of your account at [setasign.com](https://www.setasign.com) to which your licenses
are assigned. You will be asked for this during a composer run. See 
[here](https://getcomposer.org/doc/articles/authentication-for-private-packages.md#http-basic)
for more options for authentication. 

Depending on what KMS service you want to use make sure that you setup the
authentication for them:

- [Credentials for the AWS SDK for PHP Version 3](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_credentials.html)
- [Google Cloud KMS Client Libraries](https://cloud.google.com/kms/docs/reference/libraries#setting_up_authentication)

We use authentication data from environment variables for demonstration purpose
throughout.

## How it works

We implemented two classes representing a CSR and a X509 certificate instance.
They need to be initialized by an existing CSR or certificate. For creation of 
new CSRs or certificates there's a static `create()` method in both classes which
uses standard OpenSSL functions to create the CSR and certificate.

Then there's an `update()` method that accepts either an instance of
`AwsKMS\Updater` or `GoogleCloudKMS\Updater` as its parameter.

Internally all key information, algorithms and signature were updated with the use
of the key stored in the KMS then. 

For communication with the KMS services we use the official client libraries:

- [AWS SDK for PHP Version 3](https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/welcome.html)
- [Google Cloud KMS for PHP](https://github.com/googleapis/google-cloud-php-kms)

## Create a self-signed certificate

Before you start to request a real certificate from a certificate authority or you 
simply want to test the KMS service, you can create a self-signed certificated the
following way:

### Google Cloud KMS

In Google Cloud KMS all things like algorithm, hash and padding are configured in
the key itself. So it is straight forward to create a self-signed certificate:

```php
<?php

use setasign\CloudKmsCsr\Certificate;
use setasign\CloudKmsCsr\GoogleCloudKMS;

require_once 'vendor/autoload.php';

$projectId = '<YOUR-PROJECT-ID>';
$locationId = '<YOUR-LOCATION-ID>';
$keyRingId = '<YOUR-KEY-RING-ID>';
$keyId = '<YOUR-KEY-ID>';
$versionId = '<YOUR-KEY-VERSION-ID>';

// create an updater instance
$updater = new GoogleCloudKMS\Updater($projectId, $locationId, $keyRingId, $keyId, $versionId);

// create a new Certificate
$certificate = Certificate::create([
    'commonName' => 'Test and Development',
    'organizationName' => 'Setasign GmbH & Co. KG'
]);
// or
//$certificate = new Certificate(file_get_contents('existing-x509-certificate.pem'));

// update it by the key in the KMS
$certificate->update($updater);

// verify the certifcate
echo 'Verified: ' . ($certificate->verify() ? 'YES' : 'NO');
echo "\n\n";

// output PEM encoded certifcate
echo $certificate->get();
```

### AWS KMS

Nearly the same for AWS KMS. You only have to define the signature algorithm
yourself. See [here](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose.html#key-spec-rsa-sign)
for all available algorithms. Notice that these algorithms need to be supported by the used key.

```php
<?php

use Aws\Kms\KmsClient;
use setasign\CloudKmsCsr\Certificate;
use setasign\CloudKmsCsr\AwsKMS;

require_once 'vendor/autoload.php';

$region = '<REGION>';
$version = '<VERSION>';
$keyId = '<KEY-ID>';
$signatureAlgorithm = 'RSASSA_PKCS1_V1_5_SHA_512';

$kmsClient = new KmsClient([
    'region' => $region,
    'version' => $version
]);

$updater = new AwsKms\Updater($keyId, $kmsClient);
$updater->setSignatureAlgorithm($signatureAlgorithm);

$certificate = Certificate::create([
    'commonName' => 'Test and Development',
    'organizationName' => 'Setasign GmbH & Co. KG'
]);
// or
//$certificate = new Certificate(file_get_contents('existing-x509-certificate.pem'));

// update it by the key in the KMS
$certificate->update($updater);

// verify the certifcate
echo 'Verified: ' . ($certificate->verify() ? 'YES' : 'NO');
echo "\n\n";

// output PEM encoded certifcate
echo $certificate->get();
```

### Create a CSR

Very simliar to the above examples but just use `Csr` instead of `Certifcate`.

### Google Cloud KMS

```php
<?php

use setasign\CloudKmsCsr\Csr;
use setasign\CloudKmsCsr\GoogleCloudKMS;

require_once 'vendor/autoload.php';

$projectId = '<YOUR-PROJECT-ID>';
$locationId = '<YOUR-LOCATION-ID>';
$keyRingId = '<YOUR-KEY-RING-ID>';
$keyId = '<YOUR-KEY-ID>';
$versionId = '<YOUR-KEY-VERSION-ID>';

// create an updater instance
$updater = new GoogleCloudKMS\Updater($projectId, $locationId, $keyRingId, $keyId, $versionId);

// create a new CSR
$csr = Csr::create([
    'countryName' => 'DE',
    'stateOrProvinceName' => 'Niedersachen',
    'localityName' => 'Helmstedt',
    'organizationName' => 'Setasign GmbH & Co. KG',
    'organizationalUnitName' => 'Testing and Development',
    'commonName' => 'SetaPDF-Signer',
    'emailAddress' => 'setapdf-demos@setasign.com'
]);
// or
//$csr = new Csr(file_get_contents('existing-csr.pem'));

// update it by the key in the KMS
$csr->update($updater);

// verify the CSR
echo 'Verified: ' . ($csr->verify() ? 'YES' : 'NO');
echo "\n\n";

// output PEM encoded CSR
echo $csr->get();
```

### AWS KMS

```php
<?php

use Aws\Kms\KmsClient;
use setasign\CloudKmsCsr\Csr;
use setasign\CloudKmsCsr\AwsKMS;

require_once 'vendor/autoload.php';

$region = '<REGION>';
$version = '<VERSION>';
$keyId = '<KEY-ID>';
$signatureAlgorithm = 'RSASSA_PKCS1_V1_5_SHA_512';

$kmsClient = new KmsClient([
    'region' => $region,
    'version' => $version
]);

$updater = new AwsKms\Updater($keyId, $kmsClient);
$updater->setSignatureAlgorithm($signatureAlgorithm);

$csr = Csr::create([
    'countryName' => 'DE',
    'stateOrProvinceName' => 'Niedersachen',
    'localityName' => 'Helmstedt',
    'organizationName' => 'Setasign GmbH & Co. KG',
    'organizationalUnitName' => 'Testing and Development',
    'commonName' => 'SetaPDF-Signer',
    'emailAddress' => 'setapdf-demos@setasign.com'
]);
// update it by the key in the KMS
$csr->update($updater);

// verify the CSR
echo 'Verified: ' . ($csr->verify() ? 'YES' : 'NO');
echo "\n\n";

// output PEM encoded CSR
echo $csr->get();
```