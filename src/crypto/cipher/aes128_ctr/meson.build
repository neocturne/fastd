if get_option('cipher_aes128-ctr').disabled()
	subdir_done()
endif

impls = []
subdir('openssl')
ciphers += { 'aes128-ctr' : impls }

src += files('aes128_ctr.c')

