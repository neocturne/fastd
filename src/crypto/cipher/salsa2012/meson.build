if get_option('cipher_salsa2012').disabled()
	subdir_done()
endif

impls = []
subdir('nacl')
subdir('xmm')
ciphers += { 'salsa2012' : impls }

src += files('salsa2012.c')
