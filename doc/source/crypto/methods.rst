Method providers
================

See :doc:`/manual/methods` for details about the method
configuration and recommendations.

generic-gmac
~~~~~~~~~~~~

The *generic-gmac* provider combines the GHASH message authetication code
with any stream cipher, which is used both to encrypt the data and the
authentication tag.

After the last encrypted data block, a block containing the length of
the data (in bits, big endian) is passed to the GHASH function as defined
by the GCM specification.

The method names normally have the form "<cipher>+gmac", and "aes128-gcm"
for the AES128 cipher.

composed-gmac
~~~~~~~~~~~~~

The *composed-gmac* provider combines the GHASH message authetication code
with two stream ciphers, where the first one is used to encrypt the data and the second one for the
authentication tag. As only the authentication tag must be encrypted, "null" can be used
as the first cipher for authenticated-only methods.

After the last encrypted data block, a block with the first 8 bytes containing the length of
the data (in bits, big endian) and the other 8 bytes set to zero is passed to the GHASH function.
This differs from the size block used by the *generic-gmac* for historical reasons.

The method names normally have the form "<cipher>+<cipher>+gmac", and "<cipher>+aes128-gmac"
for the AES128 cipher.

generic-umac
~~~~~~~~~~~~

The *generic-umac* provider combines the UHASH message authetication code
with any stream cipher, which is used both to encrypt the data and the
authentication tag.

The method names have the form "<cipher>+umac".

composed-umac
~~~~~~~~~~~~~

The *composed-umac* provider combines the UHASH message authetication code
with two stream ciphers, where the first one is used to encrypt the data and the second one for the
authentication tag. As only the authentication tag must be encrypted, "null" can be used
as the first cipher for authenticated-only methods.

The method names have the form "<cipher>+<cipher>+umac".

generic-poly1305
~~~~~~~~~~~~~~~~

The *generic-umac* provider combines the `Poly1305 <http://cr.yp.to/mac.html>`_ message authentication code
with any stream cipher, which is used both to encrypt the data and the
authentication tag. This method was added to replace the deprecated *xsalsa20-poly1305*
method, but may be removed as well in the long term as UMAC is generally more performant
and makes the same security guarantees.

The method names have the form "<cipher>+poly1305".

xsalsa20-poly1305
~~~~~~~~~~~~~~~~~

The *xsalsa20-poly1305* provider only provides a single method, "xsalsa20-poly1305",
which uses the "secret box" provided by the `NaCl <http://nacl.cr.yp.to/>`_ library.
It is deprecated and should be used for connections with very old fastd versions only.

null
~~~~

The "null" method doesn't provide any encryption or authentication.

cipher-test
~~~~~~~~~~~

The *cipher-test* method can be used to run a cipher without any authentication.
This isn't secure and should be used for tests and benchmarks only.

The method names have the form "<cipher>+cipher-test".
