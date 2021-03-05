Protocol specification
======================

Basic protocol design
~~~~~~~~~~~~~~~~~~~~~
fastd uses UDP as the transport protocol for its packets. UDP has been chosen
instead of raw IP packets (as they are used by IPIP and 6in4 tunnels or IPsec)
to simplify the deployment of multiple fastd instances on the same host using different
UDP ports and allow passing through common NAT routers without explicit configuration.

The first byte of the UDP payload is used to discern the different packet types
used by fastd. Since fastd v22, the following packet types are used:

- ``0x00`` Data packet (v22+)
- ``0x01`` Handshake packet (pre-v22)
- ``0x02`` Data packet (pre-v22)
- ``0xC8`` L2TP control message header (v22+)

fastd v22 still supports the pre-v22 packet types, so communication between old
and new versions is possible.

L2TP control message headers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since fastd v22, all handshake packets may be prefixed with an L2TP control message header to make
sure these packets are not considered data packets by the L2TP kernel code even with potential
future extensions of the L2TP protocol. The basic format of this header is the following
(as specified in `RFC3931 <https://tools.ietf.org/html/rfc3931>`_)::

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |T|L|x|x|S|x|x|x|x|x|x|x|  Ver  |             Length            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Control Connection ID                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |               Ns              |               Nr              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

When sending a packet with an L2TP header, the following rules apply:

- Only the *T*, *L*, and *S* flags are set (first byte is ``0xC8``)
- *Ver* is set to 3 (second byte is ``0x03``)
- *Length* is set to 12 (only the header itself is counted)
- *Control Connection ID*, *Ns* and *Nr* are unused, they are set to 0

When receiving packets, only the first two bytes are verified. Packets with unexpected values in these bytes
are discarded.

When replying to a handshake packet, fastd will insert the L2TP header when the peer has signaled that it
supports such packets using the *L2TP_SUPPORT* flag. Initial handshakes will be sent twice at the same
time, once with and once without an L2TP header, so both new and old versions of fastd can be supported.

fastd v22 and newer ignore handshake packets without L2TP header when the *L2TP_SUPPORT* flag is set, so
only one of the two handshake packets with identical content will be handled.

In addition to handshakes, data packets may be prefixed with such L2TP control message headers as well, but
this is rarely useful, as it reduces the usable MTU of a tunnel. The "null\@l2tp" method makes use of this
for keepalive packets, so they are passed up to the fastd userspace when using the L2TP kernel offload feature.

Handshake format
~~~~~~~~~~~~~~~~
The first 4 bytes (after the L2TP header if it exists, of the packet otherwise) form the handshake header::

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      0x01     |      0x00     |          TLV Length           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The rest of the handshake packet consists of TLV records, the total length of which is given by the *TLV Length*
header field (in big-endian byte order).

Each of the following TLV records starts with a 2-byte type field, followed by a 2-byte length field and the
arbitrary-length value. There is no special alignment defined for the TLV records. All integers that are part of
the TLV format (in particular, the type and length fields) are encoded in little-endian byte order.

TLV record types
----------------
========== ============================= ========================== ===================================================================
Record ID  Value description             Format                     Values
========== ============================= ========================== ===================================================================
``0x0000`` Handshake type                1-byte unsigned integer    {1, 2, 3}
``0x0001`` Reply code                    1-byte unsigned integer    {0 (success), 1 (mandatory record missing), 2 (unacceptable value)}
``0x0002`` Error detail                  1/2-byte unsigned integer  Record type which caused an error
``0x0003`` Flags                         variable-length bit field  L2TP_SUPPORT=0x01 (sender supports L2TP control message headers)
``0x0004`` Mode                          1-byte unsigned integer    {0 (TAP mode), 1 (TUN mode)}
``0x0005`` Protocol name                 variable-length string     "ec25519-fhmqvc"
``0x0006`` Sender key                    32-byte public key
``0x0007`` Recipient key                 32-byte public key
``0x0008`` Sender handshake key          32-byte public key
``0x0009`` Recipient handshake key       32-byte public key
``0x000a`` Authentication tag (obsolete) 32-byte opaque value       Not used anymore
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
since v11.

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

* Byte 1: Packet type (``0x00`` when both sides of a connection are fastd v22 or newer, ``0x02`` otherwise)
* Byte 2: Flags (method-specific; unused, always ``0x00``)
* Bytes 3-8: Packet sequence number/nonce (big endian; incremented by 2 for each packet; one side of a connection uses the even sequence numbers and the other side the odd ones)
* Bytes 9-24: Authentication tag (method-specific)

The "null" method uses only a 1-byte header: The packet type is directly followed by the payload data.

The "null\@l2tp" method uses an 8-byte header, which is the same as the L2TPv3 Session Header over UDP, with no Cookie and
no L2-Specific Sublayer (as specified in `RFC3931 <https://tools.ietf.org/html/rfc3931>`_). fastd always uses the L2TP Session ID 1.
