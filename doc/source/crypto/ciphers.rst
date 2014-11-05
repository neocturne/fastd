Ciphers
=======
Generally, all ciphers used by fastd
are `stream ciphers <http://en.wikipedia.org/wiki/Stream_cipher>`_.

This means that the cipher outputs a cipher stream indistinguishable
from a random byte stream which can be used to encrypt packets of any
length without a need for padding the packet site to a multiple of a
block size by just XORing the cipher stream with the packet.

AES128-CTR
~~~~~~~~~~
The Advanced Encryption Standard is a widely used, highly regarded block cipher
specified in [FIPS197]_.

In counter mode a nonce of up to 12 bytes in concatenated with a 4 byte counter;
this value is encrypted with the block cipher to compute 16 bytes of the cipher stream.

AES128 has been chosen in contrast to the stronger variants AES192 and AES256 as
hardware acceleration for AES128 is more widely available on embedded hardware.
Using this acceleration hardware from userspace through the
alg_if interface of the Linux kernel is very complex though, so support for it has
been removed from fastd again (but may still be used through OpenSSL.

One issue with the AES algorithm is that it is very hard to implement in a way
that is safe against cache timing attacks (see [Ber05a]_ for details). Because
of that fastd can make use of two different AES implementations: a very secure, but
also very slow implementation from the `NaCl <http://nacl.cr.yp.to/>`_ library, and
the implementations from OpenSSL (which can either use hardware acceleration like AES-NI,
or a fast, but potentially insecure software implementation).

Salsa20(/12)
~~~~~~~~~~~~
Salsa20 (see [Ber07]_) is a state-of-the-art stream cipher which is very fast and very secure. In contrast to
AES, it is easily implementable without any timing side channels.

Salsa20/12 is a variant of Salsa20 which uses only 12 instead of 20 rounds
to improve performance. The Salsa20/12 has been chosen for the software profile on the `eSTREAM <http://www.ecrypt.eu.org/stream/>`_ portfolio in
2011 as it has a very high throughput while providing a very comfortable security margin.

The even more reduced variant Salsa20/8 has also been evaluated for fastd,
but the performance gain has been to small to warrant the significantly
reduced security.

Bibliography
~~~~~~~~~~~~
.. [Ber05a]
   D. J. Bernstein, "Cache-timing attacks on AES", 2005. [Online]
   http://cr.yp.to/antiforgery/cachetiming-20050414.pdf

.. [Ber07]
   D. J. Bernstein, "The Salsa20 family of stream ciphers", 2007. [Online]
   http://cr.yp.to/snuffle/salsafamily-20071225.pdf

.. [FIPS197]
   National Institute of Standards and Technology, "ADVANCED ENCRYPTION STANDARD (AES)",
   Federal Information Processing Standard 197, 2001. [Online]
   http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
