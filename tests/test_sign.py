__author__ = 'simon'

from sign import sign
from verify import verify
from tests.test_support import test_wrapper


if __name__ == '__main__':
    test_wrapper(sign, None, None, None)
    test_wrapper(sign, 'cln512x', None, None)
    test_wrapper(sign, None, 'test.dat', None)
    test_wrapper(sign, None, None, 'test.dat.sgn')
    test_wrapper(sign, 'cln512x', 'test.dat', 'test.dat.sgn')
    test_wrapper(verify, 'cln512x', 'test.dat.sgn')
