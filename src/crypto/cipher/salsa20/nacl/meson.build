if get_option('cipher_salsa20_nacl').disabled()
	subdir_done()
endif

impls += 'nacl'
src += files('salsa20_nacl.c')
need_libsodium_nacl = true
