if get_option('cipher_salsa2012_xmm').disabled()
	subdir_done()
endif

if host_machine.cpu_family() == 'x86_64'
	asm_impl = 'salsa2012_amd64_xmm6.s'
elif host_machine.cpu_family() == 'x86'
	asm_impl = 'salsa2012_x86_xmm5.s'
elif get_option('cipher_salsa2012_xmm').auto()
	subdir_done()
else
	error('cipher_salsa2012_xmm is only available on x86')
endif

impls += 'xmm'
src += files('salsa2012_xmm.c', asm_impl)
