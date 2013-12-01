if(ARCH_X86_64)
  fastd_cipher_impl(salsa20 xmm
    salsa20_xmm.c
    salsa20_amd64_xmm6.s
  )
endif(ARCH_X86_64)

if(ARCH_X86)
  fastd_cipher_impl(salsa20 xmm
    salsa20_xmm.c
    salsa20_x86_xmm5.s
  )
endif(ARCH_X86)
