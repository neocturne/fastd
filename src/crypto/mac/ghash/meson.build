if get_option('mac_ghash').disabled()
	subdir_done()
endif

impls = []
subdir('builtin')
subdir('pclmulqdq')
macs += { 'ghash' : impls }

src += files('ghash.c')
