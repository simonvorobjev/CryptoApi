__author__ = 'simon'

from ctypes import *
import os

# Загрузка библиотеки
if os.name == 'nt':
    crypt_dll = windll.LoadLibrary("C:\\Windows\\System32\\crypt32.dll")
    capi10_dll = windll.LoadLibrary("C:\\Windows\\System32\\advapi32.dll")
else:
    crypt_dll = cdll.LoadLibrary("/opt/cprocsp/lib/amd64/libcapi20.so.4.0.5")
    capi10_dll = cdll.LoadLibrary("/opt/cprocsp/lib/amd64/libcapi10.so.4.0.5")

# Константы для работы с криптоапи
CRYPT_VERIFYCONTEXT = 0xF0000000
PROV_GOST_2012_256 = 80
PP_NAME = 4

# Определение всех необходимых для получения расширения структур (смотри msdn на szOID_SUBJECT_ALT_NAME2)
class CRYPT_DATA_BLOB(Structure):
    _fields_ = [("cbData", c_ulong),
                ("pbData", POINTER(c_ubyte))]

class CERT_OTHER_NAME(Structure):
    _fields_ = [("pszObjId", c_char_p),
                ("Value", CRYPT_DATA_BLOB)]

class CERT_ALT_NAME_ENTRY_UNION(Union):
    _fields_ = [("pOtherName", POINTER(CERT_OTHER_NAME)),
                ("pwszRfc822Name", c_wchar_p),
                ("pwszDNSName", c_wchar_p),
                ("DirectoryName", CRYPT_DATA_BLOB),
                ("pwszURL", c_wchar_p),
                ("IPAddress", CRYPT_DATA_BLOB),
                ("pszRegisteredID", c_char_p)]

class CERT_ALT_NAME_ENTRY(Structure):
    _anonymous_ = ("u",)
    _fields_ = [("dwAltNameChoice", c_ulong),
                ("u", CERT_ALT_NAME_ENTRY_UNION)]

class CERT_ALT_NAME_INFO(Structure):
    _fields_ = [("cAltEntry", c_ulong),
                ("rgAltEntry", POINTER(CERT_ALT_NAME_ENTRY))]

class CERT_EXTENSION(Structure):
    _fields_ = [("pszObjId", c_char_p),
                ("fCritical", c_bool),
                ("Value", CRYPT_DATA_BLOB)]

class CERT_EXTENSIONS(Structure):
    _fields_ = [("cExtension", c_ulong),
                ("rgExtension", POINTER(CERT_EXTENSION))]

# Определения констант
CERT_ALT_NAME_REGISTERED_ID = 9
CERT_ALT_NAME_DNS_NAME = 3
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
X509_ALTERNATE_NAME = 12
szOID_CERT_EXTENSIONS = "1.3.6.1.4.1.311.2.1.14"
szOID_SUBJECT_ALT_NAME2 = "2.5.29.17"

CERT_STORE_PROV_SYSTEM_W = 10
CERT_STORE_PROV_SYSTEM = CERT_STORE_PROV_SYSTEM_W
CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
CERT_SYSTEM_STORE_CURRENT_USER_ID = 1
CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2
CERT_SYSTEM_STORE_LOCATION_SHIFT = 16
CERT_SYSTEM_STORE_CURRENT_USER = (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
CERT_SYSTEM_STORE_LOCAL_MACHINE = (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
HCERTSTORE = c_void_p
HCRYPTPROV = c_ulong
HCRYPTMSG = c_void_p
NCRYPT_KEY_HANDLE = c_ulong
LPSTR = c_char_p
LPCSTR = LPSTR
LPWSTR = c_wchar_p
DWORD = c_ulong
BYTE = c_ubyte
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CERT_COMPARE_ANY = 0
CERT_COMPARE_NAME_STR_W = 8
CERT_COMPARE_SHIFT = 16
CERT_INFO_SUBJECT_FLAG = 7
CERT_FIND_ANY = (CERT_COMPARE_ANY << CERT_COMPARE_SHIFT)
CERT_FIND_SUBJECT_STR_W = CERT_COMPARE_NAME_STR_W << CERT_COMPARE_SHIFT | CERT_INFO_SUBJECT_FLAG
CERT_X500_NAME_STR = 3
CERT_CLOSE_STORE_FORCE_FLAG = 0x00000001
TRUE = 1
FALSE = 0
CMSG_SIGNER_COUNT_PARAM = 5
CMSG_CONTENT_PARAM = 2
CMSG_CERT_PARAM = 12
CMSG_SIGNED = 2
CMSG_SIGNER_CERT_INFO_PARAM = 7
CRYPT_E_ATTRIBUTES_MISSING = 0x8009100F
CMSG_VERIFY_SIGNER_CERT = 2
CMSG_CTRL_VERIFY_SIGNATURE_EX = 19
CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001
CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004

# public key
szOID_CP_GOST_R3410EL = "1.2.643.2.2.19"
szOID_CP_GOST_R3410_12_256 = "1.2.643.7.1.1.1.1"
szOID_CP_GOST_R3410_12_512 = "1.2.643.7.1.1.1.2"
# hash
szOID_CP_GOST_R3411 = "1.2.643.2.2.9"
szOID_CP_GOST_R3411_12_256 = "1.2.643.7.1.1.2.2"
szOID_CP_GOST_R3411_12_512 = "1.2.643.7.1.1.2.3"
szOID_OIWSEC_sha1 = "1.3.14.3.2.26"
szOID_NIST_sha256 = "2.16.840.1.101.3.4.2.1"


class CRYPT_IDENTIFIER(Structure):
    _fields_ = [("pszObjId", LPSTR),
                ("Parameters", CRYPT_DATA_BLOB)]


class FILETIME(Structure):
    _fields_ = [("dwLowDateTime", c_uint),
                ("dwHighDateTime", c_uint)]


class CERT_PUBLIC_KEY_INFO(Structure):
    _fields_ = [("Algorithm", CRYPT_IDENTIFIER),
                ("PublicKey", CRYPT_DATA_BLOB)]


class CERT_INFO(Structure):
    _fields_ = [("dwVersion", DWORD),
                ("SerialNumber", CRYPT_DATA_BLOB),
                ("SignatureAlgorithm", CRYPT_IDENTIFIER),
                ("Issuer", CRYPT_DATA_BLOB),
                ("NotBefore", FILETIME),
                ("NotAfter", FILETIME),
                ("Subject", CRYPT_DATA_BLOB),
                ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
                ("IssuerUniqueId", CRYPT_DATA_BLOB),
                ("SubjectUniqueId", CRYPT_DATA_BLOB),
                ("cExtension", DWORD),
                ("rgExtension", POINTER(CERT_EXTENSION))]


class CERT_CONTEXT(Structure):
    _fields_ = [("dwCertEncodingType", DWORD),
                ("pbCertEncoded", POINTER(c_ubyte)),
                ("cbCertEncoded", DWORD),
                ("pCertInfo", POINTER(CERT_INFO)),
                ("hCertStore", HCERTSTORE)]


FN_CMSG_STREAM_OUTPUT = CFUNCTYPE(c_void_p, POINTER(BYTE), DWORD, c_bool)


class CMSG_STREAM_INFO(Structure):
    _fields_ = [("cbContent", DWORD),
                ("pfnStreamOutput", POINTER(FN_CMSG_STREAM_OUTPUT)),
                ("pvArg", c_void_p)]


class CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA(Structure):
    _fields_ = [("cbSize", DWORD),
                ("hCryptProv", HCRYPTPROV),
                ("dwSignerIndex", DWORD),
                ("dwSignerType", DWORD),
                ("pvSigner", c_void_p)]

class CMSG_SIGNER_ENCODE_INFO_UNION(Union):
    _fields_ = [("hCryptProv", HCRYPTPROV),
                ("hNCryptKey", NCRYPT_KEY_HANDLE)]

class CRYPT_ATTRIBUTE(Structure):
    _fields_ = [("pszObjId", LPSTR),
                ("cValue", DWORD),
                ("rgValue", POINTER(CRYPT_DATA_BLOB))]

class CMSG_SIGNER_ENCODE_INFO(Structure):
    _anonymous_ = ("u",)
    _fields_ = [("cbSize", DWORD),
                ("pCertInfo", POINTER(CERT_INFO)),
                ("u", CMSG_SIGNER_ENCODE_INFO_UNION),
                ("dwKeySpec", DWORD),
                ("HashAlgorithm", CRYPT_IDENTIFIER),
                ("pvHashAuxInfo", c_void_p),
                ("cAuthAttr", DWORD),
                ("rgAuthAttr", POINTER(CRYPT_ATTRIBUTE)),
                ("cUnauthAttr", DWORD),
                ("rgUnauthAttr", POINTER(CRYPT_ATTRIBUTE))]

class CMSG_SIGNED_ENCODE_INFO(Structure):
    _fields_ = [("cbSize", DWORD),
                ("cSigners", DWORD),
                ("rgSigners", POINTER(CMSG_SIGNER_ENCODE_INFO)),
                ("cCertEncoded", DWORD),
                ("rgCertEncoded", POINTER(CRYPT_DATA_BLOB)),
                ("cCrlEncoded", DWORD),
                ("rgCrlEncoded", POINTER(CRYPT_DATA_BLOB))]


# определение прототипа функции CryptAcquireContextA
fCryptAcquireContextA = capi10_dll.CryptAcquireContextA
fCryptAcquireContextA.restype = c_bool
fCryptAcquireContextA.argtypes = [
    POINTER(HCRYPTPROV),   # Parameters 1 ...
    LPCSTR,
    LPCSTR,
    DWORD,
    DWORD]
# определение прототипа функции CryptGetProvParam
fCryptGetProvParam = capi10_dll.CryptGetProvParam
fCryptGetProvParam.restype = c_bool
fCryptGetProvParam.argtypes = [
    HCRYPTPROV,   # Parameters 1 ...
    DWORD,
    POINTER(BYTE),
    POINTER(DWORD),
    DWORD]
# Определяем прототип функции CryptEncodeObject
fCryptEncodeObject = crypt_dll.CryptEncodeObject
fCryptEncodeObject.restype = c_bool
fCryptEncodeObject.argtypes = [
    DWORD,   # Parameters 1 ...
    LPCSTR,
    c_void_p,
    POINTER(BYTE),
    POINTER(DWORD)]
# Определяем прототип функции CertOpenStore
fCertOpenStore = crypt_dll.CertOpenStore
fCertOpenStore.restype = HCERTSTORE
fCertOpenStore.argtypes = [
    LPCSTR,   # Parameters 1 ...
    DWORD,
    HCRYPTPROV,
    DWORD,
    c_void_p]
fCertFindCertificateInStore = crypt_dll.CertFindCertificateInStore
fCertFindCertificateInStore.restype = POINTER(CERT_CONTEXT)
fCertFindCertificateInStore.argtypes = [
    HCERTSTORE,   # Parameters 1 ...
    DWORD,
    DWORD,
    DWORD,
    c_void_p,
    POINTER(CERT_CONTEXT)]
fCertNameToStrW = crypt_dll.CertNameToStrW
fCertNameToStrW.restype = DWORD
fCertNameToStrW.argtypes = [
    DWORD,   # Parameters 1 ...
    POINTER(CRYPT_DATA_BLOB),
    DWORD,
    LPWSTR,
    DWORD]
fCertNameToStrA = crypt_dll.CertNameToStrA
fCertNameToStrA.restype = DWORD
fCertNameToStrA.argtypes = [
    DWORD,   # Parameters 1 ...
    POINTER(CRYPT_DATA_BLOB),
    DWORD,
    LPSTR,
    DWORD]
fCertCreateCertificateContext = crypt_dll.CertCreateCertificateContext
fCertCreateCertificateContext.restype = POINTER(CERT_CONTEXT)
fCertCreateCertificateContext.argtypes = [
    DWORD,
    POINTER(BYTE),
    DWORD]
fCertDuplicateCertificateContext = crypt_dll.CertDuplicateCertificateContext
fCertDuplicateCertificateContext.restype = POINTER(CERT_CONTEXT)
fCertDuplicateCertificateContext.argtypes = [POINTER(CERT_CONTEXT)]
fCertCloseStore = crypt_dll.CertCloseStore
fCertCloseStore.restype = c_bool
fCertCloseStore.argtypes = [
    HCERTSTORE,
    DWORD]
fCertFreeCertificateContext = crypt_dll.CertFreeCertificateContext
fCertFreeCertificateContext.restype = c_bool
fCertFreeCertificateContext.argtypes = [POINTER(CERT_CONTEXT)]
fCryptMsgOpenToDecode = crypt_dll.CryptMsgOpenToDecode
fCryptMsgOpenToDecode.restype = HCRYPTMSG
fCryptMsgOpenToDecode.argtypes = [
    DWORD,
    DWORD,
    DWORD,
    HCRYPTPROV,
    POINTER(CERT_INFO),
    POINTER(CMSG_STREAM_INFO)]
fCryptMsgOpenToEncode = crypt_dll.CryptMsgOpenToEncode
fCryptMsgOpenToEncode.restype = HCRYPTMSG
fCryptMsgOpenToEncode.argtypes = [
    DWORD,
    DWORD,
    DWORD,
    c_void_p,
    LPSTR,
    POINTER(CMSG_STREAM_INFO)]
fCryptMsgUpdate = crypt_dll.CryptMsgUpdate
fCryptMsgUpdate.restype = c_bool
fCryptMsgUpdate.argtypes = [
    HCRYPTMSG,
    POINTER(BYTE),
    DWORD,
    c_bool]
fCryptMsgGetParam = crypt_dll.CryptMsgGetParam
fCryptMsgGetParam.restype = c_bool
fCryptMsgGetParam.argtypes = [
    HCRYPTMSG,
    DWORD,
    DWORD,
    c_void_p,
    POINTER(DWORD)]
fCertCompareCertificate = crypt_dll.CertCompareCertificate
fCertCompareCertificate.restype = c_bool
fCertCompareCertificate.argtypes = [
    DWORD,
    POINTER(CERT_INFO),
    POINTER(CERT_INFO)]
fCryptMsgControl = crypt_dll.CryptMsgControl
fCryptMsgControl.restype = c_bool
fCryptMsgControl.argtypes = [
    HCRYPTMSG,
    DWORD,
    DWORD,
    c_void_p]
fCryptAcquireCertificatePrivateKey = crypt_dll.CryptAcquireCertificatePrivateKey
fCryptAcquireCertificatePrivateKey.restype = c_bool
fCryptAcquireCertificatePrivateKey.argtypes = [
    POINTER(CERT_CONTEXT),
    DWORD,
    c_void_p,
    POINTER(HCRYPTPROV),
    POINTER(DWORD),
    POINTER(c_bool)]
fCryptMsgClose = crypt_dll.CryptMsgClose
fCryptMsgClose.restype = c_bool
fCryptMsgClose.argtypes = [HCRYPTMSG]
fCryptMsgCalculateEncodedLength = crypt_dll.CryptMsgCalculateEncodedLength
fCryptMsgCalculateEncodedLength.restype = DWORD
fCryptMsgCalculateEncodedLength.argtypes = [DWORD,
                                            DWORD,
                                            DWORD,
                                            c_void_p,
                                            LPSTR,
                                            DWORD]