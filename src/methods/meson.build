methods = []

subdir('cipher_test')
subdir('composed_gmac')
subdir('composed_umac')
subdir('generic_gmac')
subdir('generic_poly1305')
subdir('generic_umac')
subdir('null')

method_defs = ''
method_list = ''
foreach method : methods
	method_ = method.underscorify()
	method_defs += 'extern const fastd_method_provider_t fastd_method_@0@;\n'.format(method_)
	method_list += '&fastd_method_@0@,\n'.format(method_)
endforeach

method_data = configuration_data()

method_data.set('METHOD_DEFINITIONS', method_defs)
method_data.set('METHOD_LIST', method_list)

methods_c = configure_file(
	input : 'methods.c.in',
	output : 'methods.c',
	configuration : method_data,
)
src += methods_c
src += files('common.c')
