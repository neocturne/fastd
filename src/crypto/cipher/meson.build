ciphers = {}

subdir('aes128_ctr')
subdir('null')
subdir('salsa20')
subdir('salsa2012')

cipher_defs = ''
cipher_list = ''
cipher_impls = ''
foreach cipher, impls : ciphers
	cipher_ = cipher.underscorify()

	cipher_defs += 'extern const fastd_cipher_info_t fastd_cipher_info_@0@;\n'.format(cipher_)
	cipher_list += '{"@1@", &fastd_cipher_info_@0@, cipher_@0@_impls},\n'.format(cipher_, cipher)
	cipher_impls += 'static const fastd_cipher_impl_t cipher_@0@_impls[] = {\n'.format(cipher_)

	foreach impl : impls
		impl_ = impl.underscorify()
		cipher_defs += 'extern const fastd_cipher_t fastd_cipher_@0@_@1@;\n'.format(cipher_, impl_)
		cipher_impls += '{"@2@", &fastd_cipher_@0@_@1@},\n'.format(cipher_, impl_, impl)
	endforeach

	cipher_impls += '{NULL, NULL}\n'
	cipher_impls += '};\n'.format(cipher_)

endforeach

cipher_data = configuration_data()

cipher_data.set('CIPHER_DEFINITIONS', cipher_defs)
cipher_data.set('CIPHER_LIST', cipher_list)
cipher_data.set('CIPHER_IMPLS', cipher_impls)

ciphers_c = configure_file(
	input : 'ciphers.c.in',
	output : 'ciphers.c',
	configuration : cipher_data,
)
src += ciphers_c
