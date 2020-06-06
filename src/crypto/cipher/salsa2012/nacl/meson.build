if get_option('cipher_salsa2012_nacl').disabled()
	subdir_done()
endif

impls += 'nacl'
src += files('salsa2012_nacl.c')
need_libsodium_nacl = true
