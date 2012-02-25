/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
  Partly based on QuickTun Copyright (c) 2010, Ivo Smits <Ivo@UCIS.nl>.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#ifndef _FASTD_PACKET_H_
#define _FASTD_PACKET_H_


typedef struct __attribute__ ((__packed__)) _fastd_packet_any {
	unsigned type       : 8;
	unsigned reply      : 1;
	unsigned cp         : 1;
	unsigned req_id     : 6;
	unsigned rsv        : 8;
} fastd_packet_any;

typedef struct __attribute__ ((__packed__)) _fastd_packet_request {
	unsigned type       : 8;
	unsigned reply      : 1;
	unsigned cp         : 1;
	unsigned req_id     : 6;
	unsigned rsv        : 8;
	unsigned flags      : 8;
	unsigned proto      : 8;
	unsigned method_len : 8;
	char     method_name[];
} fastd_packet_request;

typedef struct __attribute__ ((__packed__)) _fastd_packet_reply {
	unsigned type       : 8;
	unsigned reply      : 1;
	unsigned cp         : 1;
	unsigned req_id     : 6;
	unsigned rsv        : 8;
	unsigned reply_code : 8;
} fastd_packet_reply;

typedef union _fastd_packet {
	fastd_packet_any any;
	fastd_packet_request request;
	fastd_packet_reply reply;
} fastd_packet;

#endif /* _FASTD_PACKET_H_ */
