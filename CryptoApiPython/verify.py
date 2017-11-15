__author__ = 'simon'

from ctypes import *
import argparse
from crypto_support import *
from base64 import b64decode
import binascii


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


# find certificate in message
def check_for_cert_in_message(pmessage, signer_number):
    size_of_cert_param = DWORD()
    if not fCryptMsgGetParam(pmessage, CMSG_CERT_PARAM, DWORD(signer_number), None, byref(size_of_cert_param)):
        print('No certificate found!')
        return None
    else:
        # Allocating buffer for CMSG_CERT_PARAM
        cert_buffer = (c_ubyte * size_of_cert_param.value)()
        cert_buffer_pointer = cast(cert_buffer, POINTER(BYTE))
        # Check if message have certificate
        if not fCryptMsgGetParam(pmessage, CMSG_CERT_PARAM, DWORD(signer_number), cert_buffer_pointer, byref(size_of_cert_param)):
            return None
        pcert_context = fCertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                      cert_buffer_pointer,
                                                      size_of_cert_param)
        if not pcert_context:
            raise WinError()
        return pcert_context


# find certificate in dn
def check_for_cert_in_dn(signer_info, founded_certs_list):
    for cert in founded_certs_list:
        # trying to find cert in cert list
        if fCertCompareCertificate(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, signer_info, cert.contents.pCertInfo):
            return fCertDuplicateCertificateContext(cert)
    return None


def get_signer_info(pmessage, i):
    param_size = DWORD()
    # get signer info
    if not fCryptMsgGetParam(pmessage, CMSG_SIGNER_CERT_INFO_PARAM, i, None, byref(param_size)):
        raise WinError()
    signer_cert_info = (c_ubyte * param_size.value)()
    if not fCryptMsgGetParam(pmessage, CMSG_SIGNER_CERT_INFO_PARAM, i, signer_cert_info, byref(param_size)):
        raise WinError()
    return CERT_INFO.from_buffer(signer_cert_info)


def verify_signature(signature_file_name, founded_certs_list):
    # open message for signature
    pmessage = fCryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, None, None)
    if not pmessage:
        raise WinError()
    # open signature file
    signature_file = open(signature_file_name, 'rb')
    file_data = signature_file.read()
    # try to decode it as base64
    try:
        file_data = b64decode(file_data)
    except binascii.Error:
        print("der, not base 64")
    # cast file date into BYTE*
    file_data_pointer = pointer((c_ubyte * len(file_data)).from_buffer_copy(file_data))
    file_data_pointer = cast(file_data_pointer, POINTER(BYTE))
    # update message with data
    if not fCryptMsgUpdate(pmessage, file_data_pointer, len(file_data), TRUE):
        raise WinError()
    # create variables for signers count and its size
    signers_count = DWORD()
    size_of_count = sizeof(signers_count)
    size_of_count = DWORD(size_of_count)
    # get number of signers
    if not fCryptMsgGetParam(pmessage, CMSG_SIGNER_COUNT_PARAM, 0, byref(signers_count), byref(size_of_count)):
        raise WinError()
    print('Number of signers: ' + str(signers_count.value))
    # signer loop
    for i in range(signers_count.value):
        signer_info = get_signer_info(pmessage, i)
        # search for signer cert
        pcert_context = check_for_cert_in_message(pmessage, i)
        if not pcert_context:
            print('No CMSG_CERT_PARAM in message')
            # search for cert in dn certificates
            pcert_context = check_for_cert_in_dn(signer_info, founded_certs_list)
            if not pcert_context:
                print('No valid certificate in dn list')
        if pcert_context:
            # show signer
            dname_buffer = decode_subject_buffer(pcert_context.contents.pCertInfo.contents.Subject)
            print('Signer: ' + dname_buffer.value)
            # signature verification
            verify_sign_para = CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA()
            verify_sign_para.dwSignerIndex = DWORD(i)
            verify_sign_para.dwSignerType = CMSG_VERIFY_SIGNER_CERT
            verify_sign_para.pvSigner = cast(pcert_context, c_void_p)
            verify_sign_para_pointer = c_void_p(addressof(verify_sign_para))
            if not fCryptMsgControl(pmessage, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, verify_sign_para_pointer):
                print('Verification failed!')
            else:
                print('Verified! Signature checked!')


def verify(dn, signature_file):
    # found certificates to check signature
    founded_certs_list, CertStore = find_certs_in_store(b'My', dn)
    # verify signature
    verify_signature(signature_file, founded_certs_list)
    # close contexts and store
    for cert in founded_certs_list:
        fCertFreeCertificateContext(cert)
    if not fCertCloseStore(CertStore, 0):
        fCertCloseStore(CertStore, CERT_CLOSE_STORE_FORCE_FLAG)
        raise Exception('CertCloseStore cannot close store gracefully')

def main():
    # python3 verify.py --input <file> --dn <dn>
    parser = argparse.ArgumentParser(description='Verify signature')
    parser.add_argument('-i', '--input', help='Input file')
    parser.add_argument('-d', '--dn', help='Certificate DName for filtering')
    args = parser.parse_args()
    verify(args.dn, args.input)


if __name__ == '__main__':
    main()
