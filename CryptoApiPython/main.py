__author__ = 'simon'
from ctypes import *
import argparse

"""функция тестирования криптоапи

Пробует открыть контекст провайдера и узнать его имя.

"""
# Константы для работы с криптоапи
CRYPT_VERIFYCONTEXT = 0xF0000000
PROV_GOST_2012_256 = 80
PP_NAME = 4

def test_cryptoapi():
    # Загрузка библиотеки
    # mydll = windll.LoadLibrary("C:\\Windows\\System32\\advapi32.dll")
    mydll = cdll.LoadLibrary("/opt/cprocsp/lib/amd64/libcapi10.so.4.0.5")
    # определение прототипа функции CryptAcquireContextA
    fCryptAcquireContextA = mydll.CryptAcquireContextA
    fCryptAcquireContextA.restype = c_bool
    fCryptAcquireContextA.argtypes = [
        POINTER(c_ulong),   # Parameters 1 ...
        c_char_p,
        c_char_p,
        c_ulong,
        c_ulong]
    # Получаем хэндл провайдера
    handle = c_ulong()
    fCryptAcquireContextA(byref(handle), None, None, PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)
    # определение прототипа функции CryptGetProvParam
    fCryptGetProvParam = mydll.CryptGetProvParam
    fCryptGetProvParam.restype = c_bool
    fCryptGetProvParam.argtypes = [
        c_ulong,   # Parameters 1 ...
        c_ulong,
        POINTER(c_ubyte),
        POINTER(c_ulong),
        c_ulong]
    # Получаем длину строки имени
    cbData = c_ulong()
    fCryptGetProvParam(handle, PP_NAME, None, byref(cbData), 0)
    # Выделяем буфер для имени провайдера
    pbData = (c_ubyte * cbData.value)()
    # Получаем имя провайдера
    fCryptGetProvParam(handle, PP_NAME, pbData, byref(cbData), 0)
    provname = cast(pbData, c_char_p)
    print(provname.value)

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

"""функция получения закодированного расшириения с dns-именами

Создаёт расширение из переданного списка dns-имён, и пишет его в выходной файл

dns_names - список строк с dns-именами

output_file - имя файла для итоговой записи

"""

def create_ext(dns_names, output_file):
    # Открываем библиотеку
    # mydll = windll.LoadLibrary("C:\\Windows\\System32\\crypt32.dll")
    mydll = cdll.LoadLibrary("/opt/cprocsp/lib/amd64/libcapi20.so.4.0.5")
    # Определяем прототип функции CryptEncodeObject
    fCryptEncodeObject = mydll.CryptEncodeObject
    fCryptEncodeObject.restype = c_bool
    fCryptEncodeObject.argtypes = [
        c_ulong,   # Parameters 1 ...
        c_char_p,
        c_void_p,
        POINTER(c_ubyte),
        POINTER(c_ulong)]
    # Создаём переменную для хранения CERT_ALT_NAME_INFO
    alt_name_info = CERT_ALT_NAME_INFO()
    # Инициализируем число dns-имён нулём
    alt_name_info.cAltEntry = c_ulong(0)
    # Создаём массив CERT_ALT_NAME_ENTRY размера количества dns-имён
    elems = (CERT_ALT_NAME_ENTRY * len(dns_names))()
    # Записываем массив в alt_name_info
    alt_name_info.rgAltEntry = cast(elems, POINTER(CERT_ALT_NAME_ENTRY))
    # Запускаем цикл для заполнения массива
    for idx, dns_name in enumerate(dns_names):
        # Создаём элемент для массива
        alt_name_entry = CERT_ALT_NAME_ENTRY()
        # Заполняем dns-имя
        alt_name_entry.pwszDNSName = c_wchar_p(dns_name)
        # Выставляем значение элемента union'а в dns-имя
        alt_name_entry.dwAltNameChoice = c_ulong(CERT_ALT_NAME_DNS_NAME)
        # Увеличиваем счётчик элеметов массива на один
        alt_name_info.cAltEntry += 1
        # Пишем в массив созданный элемент
        alt_name_info.rgAltEntry[alt_name_info.cAltEntry - 1] = alt_name_entry
    # Кодируем альтернативное имя, для чего сначала получаем размер выходных данных
    cbData = c_ulong()
    success = fCryptEncodeObject(c_ulong(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
                       c_char_p(X509_ALTERNATE_NAME),
                       c_void_p(addressof(alt_name_info)),
                       None,
                       byref(cbData))
    if not success:
        raise WinError()
    # Выделяем память для выходных данных
    pbData = (c_ubyte * cbData.value)()
    # Кодируем альтернативное имя
    fCryptEncodeObject(c_ulong(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
                       c_char_p(X509_ALTERNATE_NAME),
                       c_void_p(addressof(alt_name_info)),
                       pbData,
                       byref(cbData))
    # Создаём элемент расширения сертификата
    cert_ext = CERT_EXTENSION()
    # Заполняем OID расширения
    cert_ext.pszObjId = c_char_p(szOID_SUBJECT_ALT_NAME2.encode('utf-8'))
    cert_ext.fCritical = False
    # Заполняем размер данных
    cert_ext.Value.cbData = cbData
    # Выставляем указатель на наше закодированное альтернативное имя
    cert_ext.Value.pbData = pbData
    # Создаём массив расширений сертификата
    cert_exts = CERT_EXTENSIONS()
    # Там всего один элемент - наше расширение альтернативного имени
    cert_exts.cExtension = 1
    # Выставляем указатель на наше расширение
    cert_exts.rgExtension = pointer(cert_ext)
    # Получаем размер итогового расширения
    final_cbData = c_ulong()
    success = fCryptEncodeObject(c_ulong(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
                       c_char_p(szOID_CERT_EXTENSIONS.encode('utf-8')),
                       c_void_p(addressof(cert_exts)),
                       None,
                       byref(final_cbData))
    if not success:
        raise WinError()
    # Выделяем память для итоговых данных
    final_pbData = (c_ubyte * final_cbData.value)()
    # Кодируем расширение сертификата
    fCryptEncodeObject(c_ulong(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
                       c_char_p(szOID_CERT_EXTENSIONS.encode('utf-8')),
                       c_void_p(addressof(cert_exts)),
                       final_pbData,
                       byref(final_cbData))
    # Преобразуем в строку, которую можно будет записать в выходной файл
    final_data = cast(final_pbData, c_char_p).value
    # Открываем файл
    f = open(output_file, 'wb')
    # Пишем туда данные (в данных лишний asn-элемент в первых двух символах, отбрасываем его
    f.write(final_data[2:final_cbData.value])
    # Закрываем файл
    f.close()

def main():
    # Парсер входных аргументов: передаём строки dns имён и параметр --output для имени итогового файла:
    # python3 main.py <dns1> <dns2> ... <dnsN> --output <file>
    parser = argparse.ArgumentParser(description='Create an altname dns extension for cryptcp -ext.')
    parser.add_argument('dns_names', metavar='dns_names', type=str, nargs='+',
                   help='an dns name for the extension')
    parser.add_argument('-o', '--output', help='output file')
    args = parser.parse_args()
    # Вызываем кодирование расширения
    create_ext(args.dns_names, args.output)

if __name__ == '__main__':
    main()