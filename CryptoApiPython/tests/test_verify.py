__author__ = 'simon'

from verify import verify
from tests.test_support import test_wrapper


if __name__ == '__main__':
    test_wrapper(verify, None, None)
    test_wrapper(verify, 'cln512x', None)
    test_wrapper(verify, None, 'test.dat.sgn')
    test_wrapper(verify, 'cln512x', 'test.dat.sgn')
