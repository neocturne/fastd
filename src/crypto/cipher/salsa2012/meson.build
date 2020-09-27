if get_option('cipher_salsa2012').disabled()
	subdir_done()
endif

impls = []
subdir('xmm')
subdir('nacl')
ciphers += { 'salsa2012' : impls }

src += files('salsa2012.c')
