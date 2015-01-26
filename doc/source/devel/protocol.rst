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
For historical reasons, there are two different TLV encodings: all multi-byte values mentioned in the handshake specification
may be transmitted either in big endian or in little endian byte order. As fastd versions before v17 only understand the old
little endian format, fastd will always transmit its handshake as little endian to maintain compatiblity, but it can also
understand and correctly handle the new big endian format to support future fastd versions which will use the new format.

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

.. _handshake_protocol:

Handshake protocol
------------------
The following specification describes the current handshake as it is performed by fastd versions
since v11 when secure handshakes are enabled.

The handshake protocol consists of three packets. See also: :doc:`/crypto/ec25519`, :doc:`/crypto/fhmqvc`

The following fields are sent in all three packets as different fastd versions expect them in
different parts of the handshake:

* Mode (TUN/TAP)
* MTU
* fastd version (e.g. ``v15``)
* Protocol name (``ec25519-fhmqvc``)

Handshake request
.................
The first packet of a handshake contains the following additional fields:

* Handshake type (0x01)
* FHMQV-C values:

  - Sender key :math:`\hat{A}`
  - Recipient key :math:`\hat{B}`
  - Sender handshake key :math:`X`

The recipient key may be omitted if the recipient identity is unknown because the handshake was triggered by an unexpected data packet.

Handshake reply
...............
The second packet of a handshake contains the following additional fields:

* Handshake type (0x02)
* Reply code (0x00)
* Method list (list of all supported methods)
* FHMQV-C values:

  - Sender key :math:`\hat{B}`
  - Recipient key :math:`\hat{A}`
  - Sender handshake key :math:`Y`
  - Recipient handshake key :math:`X`
  - TLV authentication tag :math:`\text{MAC}_B`

Handshake finish
................
The second packet of a handshake contains the following additional fields:

* Handshake type (0x03)
* Reply code (0x00)
* Method (the chosen encryption/authentication scheme)
* FHMQV-C values:

  - Sender key :math:`\hat{A}`
  - Recipient key :math:`\hat{B}`
  - Sender handshake key :math:`X`
  - Recipient handshake key :math:`Y`
  - TLV authentication tag :math:`\text{MAC}_A`

Handshake error
...............
When an unacceptable handshake is received, fastd will respond with an error packet. The error packet contains the following fields:

* Handshake type (the type of the packet that is answered plus 1)
* Reply code (0x01 when a record is missing from the handshake,
  0x02 when a value is unacceptable)
* Error detail (the record type ID which caused the error)

Payload packets
~~~~~~~~~~~~~~~
The payload packet structure is defined by the methods; at the moment most methods use the same format, starting with a 24 byte header, followed by the actual payload:

* Byte 1: Packet type (0x02)
* Byte 2: Flags (method-specific; unused, always 0x00)
* Bytes 3-8: Packet sequence number/nonce (big endian; incremented by 2 for each packet; one side of a connection uses the even sequence numbers and the other side the odd ones)
* Bytes 9-24: Authentication tag (method-specific)

The ``null`` method uses only a 1 byte header: The packet type is directly followed by the payload data.

In the legacy ``xsalsa20-poly1305`` method, the flag and nonce fields are reversed and the nonce is in little endian for compatiblity reasons.
