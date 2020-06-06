macs = {}

subdir('ghash')
subdir('uhash')

mac_defs = ''
mac_list = ''
mac_impls = ''
foreach mac, impls : macs
	mac_ = mac.underscorify()

	mac_defs += 'extern const fastd_mac_info_t fastd_mac_info_@0@;\n'.format(mac_)
	mac_list += '{"@1@", &fastd_mac_info_@0@, mac_@0@_impls},\n'.format(mac_, mac)
	mac_impls += 'static const fastd_mac_impl_t mac_@0@_impls[] = {\n'.format(mac_)

	foreach impl : impls
		impl_ = impl.underscorify()
		mac_defs += 'extern const fastd_mac_t fastd_mac_@0@_@1@;\n'.format(mac_, impl_)
		mac_impls += '{"@2@", &fastd_mac_@0@_@1@},\n'.format(mac_, impl_, impl)
	endforeach

	mac_impls += '{NULL, NULL}\n'
	mac_impls += '};\n'.format(mac_)

endforeach

mac_data = configuration_data()

mac_data.set('MAC_DEFINITIONS', mac_defs)
mac_data.set('MAC_LIST', mac_list)
mac_data.set('MAC_IMPLS', mac_impls)

macs_c = configure_file(
	input : 'macs.c.in',
	output : 'macs.c',
	configuration : mac_data,
)
src += macs_c
