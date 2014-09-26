Protocol specification
======================

Basic protocol design
~~~~~~~~~~~~~~~~~~~~~
fastd uses UDP as the transport protocol for its packets. UDP has been chosen
instead of raw IP packets (as they are used by IPIP and 6in4 tunnels or IPsec)
to simplify the deployment of multiple fastd instances on the same host using different
UDP ports and allow passing through common NAT routers without explicit configuration.

The first byte of the UDP payload is used to discern the different packet types
used by fastd. For now only two values for the first byte have been defined:
``0x01`` indicates a handshake packet, and ``0x02`` a data packet. All other
values are reserved for future use and must be ignored by current implementations.

Handshake format
~~~~~~~~~~~~~~~~
For historical reasons, all multi-byte values mentioned in the handshake specification are transmitted in Little Endian byte order
unless specified otherwise.

The initial ``0x01`` byte together with the next three bytes form the 4-byte handshake header; the rest of
the packet after the header consists of a list of TLV records. The second header byte is reserved and must
always be ``0x00``; the following two header bytes contain the length of the following TLV records in bytes
encoded as Big Endian.

The following TLV records start with a 2-byte type field, followed by a 2-byte length field and the
arbitrary-length value. There is no special alignment defined for the TLV records.


TLV record types
----------------
========== ============================= ========================== ===================================================================
Record ID  Value description             Format                     Values
========== ============================= ========================== ===================================================================
``0x0000`` Handshake type                1-byte unsigned integer    {1, 2, 3}
``0x0001`` Reply code                    1-byte unsigned integer    {0 (success), 1 (mandatory record missing), 2 (unacceptable value)}
``0x0002`` Error detail                  1/2-byte unsigned integer  Record type which caused an error
``0x0003`` Flags (currently unused)      variable-length bit field  So far, no values are defined
``0x0004`` Mode                          1-byte unsigned integer    {0 (TAP mode), 1 (TUN mode)}
``0x0005`` Protocol name                 variable-length string     "ec25519-fhmqvc"
``0x0006`` Sender key                    32-byte public key
``0x0007`` Recipient key                 32-byte public key
``0x0008`` Sender handshake key          32-byte public key
``0x0009`` Recipient handshake key       32-byte public key
``0x000a`` Authentication tag (obsolete) 32-byte opaque value       Not used if secure handshakes are enabled
``0x000b`` MTU                           2-byte unsigned integer
``0x000c`` Method name                   variable-length string
``0x000d`` Version name                  variable-length string
``0x000e`` Method list                   zero-separated string list
``0x000f`` TLV authentication tag        32-byte opaque value
========== ============================= ========================== ===================================================================

Handshake protocol
------------------
The following specification describes the current handshake as it is performed by fastd versions
since v11 when secure handshakes are enabled.

The handshake protocol consists of three packets. See also: FHMQV-C

Handshake request
.................


Handshake reply
...............


Handshake finish
................


Payload packets
~~~~~~~~~~~~~~~
