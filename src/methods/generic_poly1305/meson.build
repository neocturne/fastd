if get_option('method_generic-poly1305').disabled()
	subdir_done()
endif

methods += 'generic-poly1305'
src += files('generic_poly1305.c')
need_libsodium_nacl = true
