if get_option('mac_uhash').disabled()
	subdir_done()
endif

impls = []
subdir('builtin')
macs += { 'uhash' : impls }

src += files('uhash.c')
