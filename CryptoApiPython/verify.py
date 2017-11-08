__author__ = 'simon'

from ctypes import *
import argparse
from crypto_support import *

def verify():
    mydll = windll.LoadLibrary("C:\\Windows\\System32\\crypt32.dll")
    my_store = c_wchar_p(u"My")
    my_store_pointer = c_void_p(addressof(my_store))
    CertStore = fCertOpenStore(LPCSTR(CERT_STORE_PROV_SYSTEM),
                               0,
                               0,
                               CERT_SYSTEM_STORE_CURRENT_USER,
                               b'My'.decode())
    if not CertStore:
        raise WinError()
    pCertPrev = None
    pCert = fCertFindCertificateInStore(CertStore,
                                        X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
                                        0,
                                        CERT_FIND_ANY,
                                        None,
                                        pCertPrev)
    while pCert:
        name_blob = pCert.contents.pCertInfo.contents.Subject
        wchar_symbols = fCertNameToStrW(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
                       name_blob,
                       CERT_X500_NAME_STR,
                       None,
                       0)
        dname_buffer = (c_wchar * wchar_symbols)()
        final_wchar_symbols = fCertNameToStrW(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
                       name_blob,
                       CERT_X500_NAME_STR,
                       dname_buffer,
                       wchar_symbols)
        if (final_wchar_symbols != wchar_symbols):
            raise Exception("final buffer size not equals asked buffer size.")
        print(dname_buffer.value)
        pCertPrev = pCert
        pCert = fCertFindCertificateInStore(CertStore,
                                        X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
                                        0,
                                        CERT_FIND_ANY,
                                        None,
                                        pCertPrev)



def main():
    # Парсер входных аргументов: передаём входной файл, проверяем подпись:
    # python3 verify.py --input <file>
    parser = argparse.ArgumentParser(description='Verify signature.')
    parser.add_argument('-i', '--input', help='input file')
    args = parser.parse_args()
    verify()

if __name__ == '__main__':
    main()
