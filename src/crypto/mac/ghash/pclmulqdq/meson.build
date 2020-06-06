if get_option('mac_ghash_pclmulqdq').disabled()
	subdir_done()
endif

if not (host_machine.cpu_family() == 'x86_64' or host_machine.cpu_family() == 'x86')
	if get_option('mac_ghash_pclmulqdq').auto()
		subdir_done()
	else
		error('mac_ghash_pclmulqdq is only available on x86')
	endif
endif

if not (cc.has_argument('-mssse3') and cc.has_argument('-mpclmul'))
	if get_option('mac_ghash_pclmulqdq').auto()
		subdir_done()
	else
		error('mac_ghash_pclmulqdq requires a compiler that supports the -mssse3 and -mpclmul options')
	endif
endif

impls += 'pclmulqdq'
src += files('ghash_pclmulqdq.c')
libs += static_library(
	'mac_ghash_pclmulqdq_impl',
	sources : ['ghash_pclmulqdq_impl.c'],
	include_directories : [srcdir],
	c_args : ['-mssse3', '-mpclmul'],
)
