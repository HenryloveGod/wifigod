/*
 * 2014 lovewilliam <ztong@vt.edu>
 */
// Copyright 2011 The Avalon Project Authors. All rights reserved.
// Use of this source code is governed by the Apache License 2.0
// that can be found in the LICENSE file.
#ifndef GS_PDU_H
#define GS_PDU_H

#include <time.h>

enum { SMS_MAX_PDU_LENGTH  = 256 };

/*
 * Encode an SMS message. Output the encoded message into output pdu buffer.
 * Returns the length of the SMS encoded message in the output buffer or
 * a negative number in case encoding failed (for example provided output buffer
 * does not have enough space).
 */
char * pdu_encode(const char* service_center_number, const char* phone_number, const char* sms_text, int buffer_size);

/*
 * Decode an SMS message. Output the decoded message into the sms text buffer.
 * Returns the length of the SMS dencoded message or a negative number in
 * case encoding failed (for example provided output buffer has not enough
 * space).
 */
int pdu_decode(const unsigned char* pdu, int pdu_len,
	       time_t* sms_time,
	       char* phone_number, int phone_number_size,
	       char* text, int text_size,
	       int* tp_dcs,
	       int* user_payload_header_size);

int ucs2_to_utf8 (int ucs2, unsigned char * utf8);

#endif   // SMS_SMS_H_
