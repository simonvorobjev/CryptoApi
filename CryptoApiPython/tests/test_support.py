__author__ = 'simon'


def test_wrapper(fcallback, *fargs):
    str_args = ''
    for farg in (*fargs), :
        str_args += str(farg) + ','
    print('------------------------------------------------------')
    print('testing ' + fcallback.__name__ + '(' + str_args + ')')
    try:
        fcallback(*fargs)
    except Exception as e:
        print("error: {0}".format(e.args))
    print('testing ' + fcallback.__name__ + '(' + str_args + ') done!')
    print('------------------------------------------------------')
    print('')
