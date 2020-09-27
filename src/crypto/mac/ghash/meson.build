if get_option('mac_ghash').disabled()
	subdir_done()
endif

impls = []
subdir('pclmulqdq')
subdir('builtin')
macs += { 'ghash' : impls }

src += files('ghash.c')
