Welcome to fastd's documentation!
=================================

fastd is a very small VPN daemon which tunnels IP packets and Ethernet frames
over UDP. It supports various modern encryption and authentication schemes and
can be used in many different network topologies (1:1, 1:n, meshed).

fastd runs on Linux, FreeBSD, OpenBSD and macOS. Android support exists in the
code, but is currently unmaintained. Binary packages are provided by many major
Linux distributions.

.. toctree::
   :caption: User manual
   :maxdepth: 2

   manual/cmdline
   manual/config
   manual/methods
   manual/mtu

.. toctree::
   :caption: Release notes
   :maxdepth: 2

   releases/v22
   releases/v21
   releases/v20
   releases/v19
   releases/v18
   releases/v17
   releases/v16
   releases/v15

.. toctree::
   :caption: Cryptographic algorithms
   :maxdepth: 2

   crypto/ec25519
   crypto/fhmqvc
   crypto/ciphers
   crypto/macs
   crypto/methods

.. toctree::
   :caption: Developer documentation
   :maxdepth: 2

   devel/building
   devel/protocol
