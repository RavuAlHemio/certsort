$openssl = "C:\OpenSSL\bin\openssl.exe"

function New-PrivateKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$OutFile
    )

    & "$openssl" `
        genpkey `
        -algorithm "RSA" `
        -pkeyopt "rsa_keygen_bits:4096" `
        -out "$OutFile"
}

function New-RootCertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Subject,

        [Parameter(Mandatory=$true,Position=1)]
        [string]$KeyFile,

        [Parameter(Mandatory=$true,Position=2)]
        [string]$OutFile,

        [int]$ValidityDays = 365
    )

    & "$openssl" `
        req `
        -new `
        -x509 `
        -utf8 `
        -days $ValidityDays `
        -subj "$Subject" `
        -addext "basicConstraints = critical, CA:TRUE" `
        -addext "subjectKeyIdentifier = hash" `
        -addext "authorityKeyIdentifier = keyid:always, issuer:always" `
        -addext "keyUsage = critical, cRLSign, digitalSignature, keyCertSign" `
        -key "$KeyFile" `
        -out "$OutFile"
}

function New-IntermediateCertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Subject,

        [Parameter(Mandatory=$true,Position=1)]
        [string]$KeyFile,

        [Parameter(Mandatory=$true,Position=2)]
        [string]$CACertFile,

        [Parameter(Mandatory=$true,Position=3)]
        [string]$CAKeyFile,

        [Parameter(Mandatory=$true,Position=4)]
        [string]$OutFile,

        [int]$ValidityDays = 365
    )

    & "$openssl" `
        req `
        -new `
        -x509 `
        -utf8 `
        -days $ValidityDays `
        -subj "$Subject" `
        -addext "basicConstraints = critical, CA:TRUE" `
        -addext "subjectKeyIdentifier = hash" `
        -addext "authorityKeyIdentifier = keyid:always, issuer:always" `
        -addext "keyUsage = critical, cRLSign, digitalSignature, keyCertSign" `
        -key "$KeyFile" `
        -CA "$CACertFile" `
        -CAkey "$CAKeyFile" `
        -out "$OutFile"
}

function New-HostCertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Subject,

        [Parameter(Mandatory=$true,Position=1)]
        [string]$KeyFile,

        [Parameter(Mandatory=$true,Position=2)]
        [string]$CACertFile,

        [Parameter(Mandatory=$true,Position=3)]
        [string]$CAKeyFile,

        [Parameter(Mandatory=$true,Position=4)]
        [string]$OutFile,

        [int]$ValidityDays = 365
    )

    & "$openssl" `
        req `
        -new `
        -x509 `
        -utf8 `
        -days $ValidityDays `
        -subj "$Subject" `
        -addext "basicConstraints = critical, CA:FALSE" `
        -addext "subjectKeyIdentifier = hash" `
        -addext "authorityKeyIdentifier = keyid:always, issuer:always" `
        -addext "keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment, keyAgreement" `
        -addext "extendedKeyUsage = critical, serverAuth" `
        -key "$KeyFile" `
        -CA "$CACertFile" `
        -CAkey "$CAKeyFile" `
        -out "$OutFile"
}

New-PrivateKey -OutFile "rootca-key.pem"
New-RootCertificate `
    -KeyFile "rootca-key.pem" `
    -OutFile "rootca-crt.pem" `
    -Subject "/CN=Honest Achmed's Used Cars and Certificates/O=Honest Achmed's Used Cars and Certificates/C=US/"

New-PrivateKey -OutFile "imed1-key.pem"
New-IntermediateCertificate `
    -KeyFile "imed1-key.pem" `
    -OutFile "imed1-crt.pem" `
    -Subject "/CN=Dishonest Ondra's Intermediate CA/O=Dishonest Ondra's Certificates/C=AT/" `
    -CACertFile "rootca-crt.pem" `
    -CAKeyFile "rootca-key.pem"

New-PrivateKey -OutFile "imed2-key.pem"
New-IntermediateCertificate `
    -KeyFile "imed2-key.pem" `
    -OutFile "imed2-crt.pem" `
    -Subject "/CN=Anonymous Liar Intermediate CA/O=Anonymous Liar's Certificates/C=AT/" `
    -CACertFile "imed1-crt.pem" `
    -CAKeyFile "imed1-key.pem"

New-PrivateKey -OutFile "leaf-key.pem"
New-HostCertificate `
    -KeyFile "leaf-key.pem" `
    -OutFile "leaf-crt.pem" `
    -Subject "/CN=*.google.com/O=Google, no, really, trust me ;-)/C=US/" `
    -CACertFile "imed2-crt.pem" `
    -CAKeyFile "imed2-key.pem"
