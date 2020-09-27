if get_option('cipher_salsa20').disabled()
	subdir_done()
endif

impls = []
subdir('xmm')
subdir('nacl')
ciphers += { 'salsa20' : impls }

src += files('salsa20.c')
