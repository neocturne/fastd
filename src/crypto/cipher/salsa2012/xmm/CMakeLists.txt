if(ARCH_X86_64)
  fastd_cipher_impl(salsa2012 xmm
    salsa2012_xmm.c
    salsa2012_amd64_xmm6.s
  )
endif(ARCH_X86_64)

if(ARCH_X86)
  fastd_cipher_impl(salsa2012 xmm
    salsa2012_xmm.c
    salsa2012_x86_xmm5.s
  )
endif(ARCH_X86)
