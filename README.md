# verify
Python CryptoApi wrapper to verify signatures.
## Usage
python3 verify.py --dn <certificate dn> --input <file with signature>
# main
Python CryptoApi test (AcquireContext with GetProvParam to get prov name) + CryptEncodeObject to create certificate extention
## Usage for creating certificate extension
python3 main.py <dns1> <dns2> ... <dnsN> --output <file>
# crypto_support
Python CryptoApi wrapping realisation
## function list
CryptAcquireContextA
CryptGetProvParam
CryptEncodeObject
CertOpenStore
CertFindCertificateInStore
CertNameToStrW
CertNameToStrA
CertCreateCertificateContext
CertDuplicateCertificateContext
CertCloseStore
CertFreeCertificateContext
CryptMsgOpenToDecode
CryptMsgUpdate
CryptMsgGetParam
CertCompareCertificate
CryptMsgControl
