__author__ = 'simon'

from ctypes import *
import argparse
from crypto_support import *


def find_certs_subject_str(CertStore, dn):
    founded_certs_list = []
    pCertPrev = None
    pCert = fCertFindCertificateInStore(CertStore,
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        0,
                                        CERT_FIND_SUBJECT_STR_W,
                                        dn,
                                        pCertPrev)
    while pCert:
        founded_certs_list.append(fCertDuplicateCertificateContext(pCert))
        print('Certificate found!')
        pCertPrev = pCert
        pCert = fCertFindCertificateInStore(CertStore,
                                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                            0,
                                            CERT_FIND_SUBJECT_STR_W,
                                            dn,
                                            pCertPrev)
    if not len(founded_certs_list):
        print('Certificate not found!')
        exit()
    return founded_certs_list


def find_certs_any(CertStore, dn):
    founded_certs_list = []
    pCertPrev = None
    pCert = fCertFindCertificateInStore(CertStore,
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        0,
                                        CERT_FIND_ANY,
                                        None,
                                        pCertPrev)
    while pCert:
        name_blob = pCert.contents.pCertInfo.contents.Subject
        wchar_symbols = fCertNameToStrW(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        name_blob,
                                        CERT_X500_NAME_STR,
                                        None,
                                        0)
        dname_buffer = (c_wchar * wchar_symbols)()
        final_wchar_symbols = fCertNameToStrW(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              name_blob,
                                              CERT_X500_NAME_STR,
                                              dname_buffer,
                                              wchar_symbols)
        if final_wchar_symbols != wchar_symbols:
            raise Exception("final buffer size not equals asked buffer size.")
        print(dname_buffer.value)
        if dname_buffer.value.find(dn) != -1:
            founded_certs_list.append(fCertDuplicateCertificateContext(pCert))
            print('Certificate found!')
        pCertPrev = pCert
        pCert = fCertFindCertificateInStore(CertStore,
                                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                            0,
                                            CERT_FIND_ANY,
                                            None,
                                            pCertPrev)
    if not len(founded_certs_list):
        print('Certificate not found!')
        exit()


def find_certs_in_store(store_name, dn):
    CertStore = fCertOpenStore(LPCSTR(CERT_STORE_PROV_SYSTEM),
                               0,
                               0,
                               CERT_SYSTEM_STORE_CURRENT_USER,
                               store_name.decode())
    if not CertStore:
        raise WinError()
    founded_certs_list = list()
    founded_certs_list += find_certs_subject_str(CertStore, dn)
    if not fCertCloseStore(CertStore, 0):
        fCertCloseStore(CertStore, CERT_CLOSE_STORE_FORCE_FLAG)
        raise Exception('CertCloseStore cannot close store gracefully')
    for cert in founded_certs_list:
        fCertFreeCertificateContext(cert)


def verify(dn):
    find_certs_in_store(b'My', dn)


def main():
    # python3 verify.py --input <file> --dn <dn>
    parser = argparse.ArgumentParser(description='Verify signature')
    parser.add_argument('-i', '--input', help='Input file')
    parser.add_argument('-d', '--dn', help='Certificate DName for filtering')
    args = parser.parse_args()
    verify(args.dn)


if __name__ == '__main__':
    main()
