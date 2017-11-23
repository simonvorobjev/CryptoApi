__author__ = 'simon'

import argparse
import crypto_support
import ctypes
from certificates import find_certs_in_store

def GetDefaultOIDfromPubKeyOID(pubKeyOID):
    # if GOST
    if (pubKeyOID == crypto_support.szOID_CP_GOST_R3410EL):
        return crypto_support.szOID_CP_GOST_R3411
    elif (pubKeyOID == crypto_support.szOID_CP_GOST_R3410_12_256):
        return crypto_support.szOID_CP_GOST_R3411_12_256
    elif (pubKeyOID == crypto_support.szOID_CP_GOST_R3410_12_512):
        return crypto_support.szOID_CP_GOST_R3411_12_512
    else:
        return crypto_support.szOID_NIST_sha256


def sign_file_with_certificate(input_file, output_file, founded_certs_list):
    signer_num = 0
    # Creating array of CMSG_SIGNER_ENCODE_INFO for all founded certs
    signer_infos = (crypto_support.CMSG_SIGNER_ENCODE_INFO * len(founded_certs_list))()
    SignInfo = crypto_support.CMSG_SIGNED_ENCODE_INFO()
    SignInfo.cSigners = len(founded_certs_list)
    SignInfo.rgSigners = ctypes.cast(signer_infos, ctypes.POINTER(crypto_support.CMSG_SIGNER_ENCODE_INFO))
    SignInfo.cbSize = ctypes.sizeof(crypto_support.CMSG_SIGNED_ENCODE_INFO)
    for cert in founded_certs_list:
        # acquire private key
        SignerInfo = crypto_support.CMSG_SIGNER_ENCODE_INFO()
        SignerInfo.cbSize = ctypes.sizeof(crypto_support.CMSG_SIGNER_ENCODE_INFO)
        acquire_flags = crypto_support.CRYPT_ACQUIRE_COMPARE_KEY_FLAG | \
                        crypto_support.CRYPT_ACQUIRE_CACHE_FLAG
        privkey_keyprov = ctypes.c_ulong()
        privkey_keyspec = ctypes.c_ulong()
        privkey_needsfree = ctypes.c_bool(crypto_support.FALSE)
        if not crypto_support.fCryptAcquireCertificatePrivateKey(cert,
                                                                 acquire_flags,
                                                                 0,
                                                                 ctypes.pointer(privkey_keyprov),
                                                                 ctypes.pointer(privkey_keyspec),
                                                                 ctypes.pointer(privkey_needsfree)):
            raise ctypes.WinError()
        SignerInfo.hCryptProv = privkey_keyprov
        SignerInfo.dwKeySpec = privkey_keyspec
        # TODO: install pin
        # fill in CMSG_SIGNER_ENCODE_INFO
        SignerInfo.HashAlgorithm.Parameters.cbData = crypto_support.DWORD(0)
        SignerInfo.pCertInfo = cert.contents.pCertInfo
        SignerInfo.cAuthAttr = crypto_support.DWORD(0)
        SignerInfo.rgAuthAttr = None
        SignerInfo.cUnauthAttr = crypto_support.DWORD(0)
        SignerInfo.rgUnauthAttr = None
        # fill in hash oid
        pubKeyOID = cert.contents.pCertInfo.contents.SubjectPublicKeyInfo.Algorithm.pszObjId
        SignerInfo.HashAlgorithm.pszObjId = crypto_support.LPSTR(
            GetDefaultOIDfromPubKeyOID(pubKeyOID.decode()).encode('utf-8'))
        # fill in CMSG_SIGNED_ENCODE_INFO
        SignInfo.rgSigners[signer_num] = SignerInfo
        signer_num += 1
        # TODO: add certificate
        # TODO: add CRL
    encoding_type = crypto_support.X509_ASN_ENCODING | crypto_support.PKCS_7_ASN_ENCODING
    # open input file
    input_file_handle = open(input_file, 'rb')
    input_file_data = input_file_handle.read()
    # cast file date into BYTE*
    file_data_pointer = ctypes.pointer((ctypes.c_ubyte * len(input_file_data)).from_buffer_copy(input_file_data))
    file_data_pointer = ctypes.cast(file_data_pointer, ctypes.POINTER(crypto_support.BYTE))
    # calculated resulting length
    encoded_len = crypto_support.fCryptMsgCalculateEncodedLength(encoding_type,
                                                                 0,
                                                                 crypto_support.CMSG_SIGNED,
                                                                 ctypes.c_void_p(ctypes.addressof(SignInfo)),
                                                                 None,
                                                                 crypto_support.DWORD(len(input_file_data)))
    # open message to encode with sign info
    message_handle = crypto_support.fCryptMsgOpenToEncode(encoding_type,
                                                          0,
                                                          crypto_support.CMSG_SIGNED,
                                                          ctypes.c_void_p(ctypes.addressof(SignInfo)),
                                                          None,
                                                          None)
    if not message_handle:
        raise ctypes.WinError()
    # update message with input data
    if not crypto_support.fCryptMsgUpdate(message_handle,
                                         file_data_pointer,
                                         len(input_file_data),
                                         crypto_support.TRUE):
        raise ctypes.WinError()
    # save signed data to file
    # Allocating buffer for CMSG_CONTENT_PARAM
    message_buffer = (ctypes.c_ubyte * encoded_len)()
    message_buffer_pointer = ctypes.cast(message_buffer, ctypes.POINTER(crypto_support.BYTE))
    # Get message content
    if not crypto_support.fCryptMsgGetParam(message_handle,
                                            crypto_support.CMSG_CONTENT_PARAM,
                                            0,
                                            message_buffer_pointer,
                                            ctypes.byref(crypto_support.DWORD(encoded_len))):
        return ctypes.WinError()
    # cast string into data to save into signature file
    signed_data = ctypes.string_at(message_buffer_pointer, encoded_len)
    # open output signature file
    output_file_handle = open(output_file, 'wb')
    #output_file_handle.write(signed_data[:encoded_len])
    output_file_handle.write(signed_data)
    output_file_handle.close()
    if not crypto_support.fCryptMsgClose(message_handle):
        raise ctypes.WinError()
    print('Successfully signed!')


def sign(dn, input_file, output_file):
    # found certificates to sign signature
    founded_certs_list, CertStore = find_certs_in_store(b'My', dn)
    # sign input file with founded certificate
    sign_file_with_certificate(input_file, output_file, founded_certs_list)
    # close contexts and store
    for cert in founded_certs_list:
        crypto_support.fCertFreeCertificateContext(cert)
    if not crypto_support.fCertCloseStore(CertStore, 0):
        crypto_support.fCertCloseStore(CertStore, crypto_support.CERT_CLOSE_STORE_FORCE_FLAG)
        raise Exception('CertCloseStore cannot close store gracefully')


def main():
    # python3 sign.py --input <file> --output <file> --dn <dn>
    parser = argparse.ArgumentParser(description='Sign file')
    parser.add_argument('-i', '--input', help='Input file')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-d', '--dn', help='Certificate DName for filtering')
    args = parser.parse_args()
    sign(args.dn, args.input, args.output)


if __name__ == '__main__':
    main()