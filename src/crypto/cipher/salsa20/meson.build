if get_option('cipher_salsa20').disabled()
	subdir_done()
endif

impls = []
subdir('nacl')
subdir('xmm')
ciphers += { 'salsa20' : impls }

src += files('salsa20.c')
