if get_option('cipher_salsa20_xmm').disabled()
	subdir_done()
endif

if host_machine.cpu_family() == 'x86_64'
	asm_impl = 'salsa20_amd64_xmm6.s'
elif host_machine.cpu_family() == 'x86'
	asm_impl = 'salsa20_x86_xmm5.s'
elif get_option('cipher_salsa20_xmm').auto()
	subdir_done()
else
	error('cipher_salsa20_xmm is only available on x86')
endif

impls += 'xmm'
src += files('salsa20_xmm.c', asm_impl)
