Encryption & authentication methods
===================================
fastd supports various combinations of ciphers and authentication schemes using
different method providers. All ciphers, message authentication codes (MACs) and
method providers can be disabled during compilation to reduce the binary size.

See `Benchmarks <https://github.com/neocturne/fastd/wiki/Benchmarks>`_ for an
overview of the performance of the different methods.

Recommended methods
~~~~~~~~~~~~~~~~~~~
The method ``salsa2012+umac`` is recommended for authenticated encyption. ``null+salsa2012+umac`` is the
recommended method for authenticated-only operation.

Salsa20/12 is a stream cipher with very high speed and a very comfortable security margin.
It has been chosed for the software profile in the `eSTREAM <http://en.wikipedia.org/wiki/ESTREAM>`_ project in 2008.

`UMAC <http://en.wikipedia.org/wiki/UMAC>`_ is an extremely fast message authentication code which is provably
secure and optimized for software implementations.

List of methods
~~~~~~~~~~~~~~~

Encrypted methods
-----------------
=======================  ================  ==========  =========  ======
Method                   Method provider   Cipher      MAC        Notes
=======================  ================  ==========  =========  ======
``aes128-gcm``           generic-gmac      aes128-ctr  ghash      [2]_
``salsa20+gmac``         generic-gmac      salsa20     ghash
``salsa2012+gmac``       generic-gmac      salsa2012   ghash
``aes128-ctr+umac``      generic-umac      aes128-ctr  uhash      [2]_
``salsa20+umac``         generic-umac      salsa20     uhash
``salsa2012+umac``       generic-umac      salsa2012   uhash
``aes128-ctr+poly1305``  generic-poly1305  aes128-ctr  none [1]_  [2]_, [3]_
``salsa20+poly1305``     generic-poly1305  salsa20     none [1]_  [3]_
``salsa2012+poly1305``   generic-poly1305  salsa2012   none [1]_  [3]_
=======================  ================  ==========  =========  ======

This list is not exhaustive. It is possible to combine different ciphers for
data and authentication tag encryption using the *composed-gmac* and *composed-umac*
method providers; these methods aren't listed here as this is not very useful.

Authenticated-only methods
--------------------------
========================  ================  ==========  =====  ======
Method                    Method provider   Cipher      MAC    Notes
========================  ================  ==========  =====  ======
``null+aes128-gmac``      composed-gmac     aes128-ctr  ghash  [2]_, [4]_
``null+salsa20+gmac``     composed-gmac     salsa20     ghash  [4]_
``null+salsa2012+gmac``   composed-gmac     salsa2012   ghash  [4]_
``null+aes128-ctr+umac``  composed-umac     aes128-ctr  uhash  [2]_, [4]_
``null+salsa20+umac``     composed-umac     salsa20     uhash  [4]_
``null+salsa2012+umac``   composed-umac     salsa2012   uhash  [4]_
========================  ================  ==========  =====  ======

Methods without security
------------------------
=============  ===============  ======  ====  =====
Method         Method provider  Cipher  MAC   Notes
=============  ===============  ======  ====  =====
``null@l2tp``  null-l2tp        none    none  [5]_
``null``       null             none    none  [5]_
=============  ===============  ======  ====  =====


.. [1] The MAC is integrated in the method provider.
.. [2] AES is very slow without OpenSSL support. OpenSSL's AES implementation may be suspect to cache timing side channels when no hardware support like AES-NI is available.
.. [3] Poly1305 is very slow on embedded systems.
.. [4] The cipher is used to encrypt the authentication tag only, the actual data is transmitted unencrypted.
.. [5] Only authentication of peers' IP addresses, but no encryption or authentication of any data is provided.
