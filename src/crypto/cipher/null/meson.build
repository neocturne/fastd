if get_option('cipher_null').disabled()
	subdir_done()
endif

impls = []
subdir('memcpy')
ciphers += { 'null' : impls }

src += files('null.c')
