__author__ = 'simon'

from crypto_support import *


# find certs with CERT_FIND_SUBJECT_STR_W by dn
def find_certs_subject_str(CertStore, dn):
    founded_certs_list = []
    pCertPrev = None
    # search for first cert
    pCert = fCertFindCertificateInStore(CertStore,
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        0,
                                        CERT_FIND_SUBJECT_STR_W,
                                        dn,
                                        pCertPrev)
    # search loop
    while pCert:
        #if cert founded - append it to final cert list
        founded_certs_list.append(fCertDuplicateCertificateContext(pCert))
        print('Certificate found!')
        pCertPrev = pCert
        # search for next cert
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


# find certs with CERT_FIND_ANY and pick from them with dn
def find_certs_any(CertStore, dn):
    founded_certs_list = []
    pCertPrev = None
    # pick any cert
    pCert = fCertFindCertificateInStore(CertStore,
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        0,
                                        CERT_FIND_ANY,
                                        None,
                                        pCertPrev)
    # search loop
    while pCert:
        # decode cert Subject with CertNameToStrW
        dname_buffer = decode_subject_buffer(pCert.contents.pCertInfo.contents.Subject)
        print(dname_buffer.value)
        # check if our dn in subject
        if dname_buffer.value.find(dn) != -1:
            founded_certs_list.append(fCertDuplicateCertificateContext(pCert))
            print('Certificate found!')
        pCertPrev = pCert
        # pick next cert
        pCert = fCertFindCertificateInStore(CertStore,
                                            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                            0,
                                            CERT_FIND_ANY,
                                            None,
                                            pCertPrev)
    if not len(founded_certs_list):
        print('Certificate not found!')


# find certificate in store
def find_certs_in_store(store_name, dn):
    # open store
    CertStore = fCertOpenStore(LPCSTR(CERT_STORE_PROV_SYSTEM),
                               0,
                               0,
                               CERT_SYSTEM_STORE_CURRENT_USER,
                               store_name.decode())
    if not CertStore:
        raise WinError()
    # create certs list
    founded_certs_list = list()
    # search for certs
    founded_certs_list += find_certs_subject_str(CertStore, dn)
    return founded_certs_list, CertStore


def decode_subject_buffer(subject):
    # get length
    wchar_symbols = fCertNameToStrW(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    subject,
                                    CERT_X500_NAME_STR,
                                    None,
                                    0)
    # create buffer
    dname_buffer = (c_wchar * wchar_symbols)()
    # convert Subject
    final_wchar_symbols = fCertNameToStrW(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                          subject,
                                          CERT_X500_NAME_STR,
                                          dname_buffer,
                                          wchar_symbols)
    # data length must be the same as was asked
    if final_wchar_symbols != wchar_symbols:
        raise Exception("final buffer size not equals asked buffer size.")
    return dname_buffer