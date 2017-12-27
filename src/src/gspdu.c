/*
 * 2014 lovewilliam <ztong@vt.edu>
 */
// Copyright 2011 The Avalon Project Authors. All rights reserved.
// Use of this source code is governed by the Apache License 2.0
// that can be found in the LICENSE file.
//
//  SMS encoding/decoding functions, which are based on examples from:
//  http://www.dreamfabric.com/sms/

#include "gspdu.h"


#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <iconv.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include "debug.h"

#include "safe.h"

typedef unsigned short UINT16;
typedef unsigned char UINT8;
typedef unsigned char BOOL;
#define TRURE (BOOL)(1)
#define FALSE (BOOL)(0)


enum {
	BITMASK_7BITS = 0x7F,
	BITMASK_8BITS = 0xFF,
	BITMASK_HIGH_4BITS = 0xF0,
	BITMASK_LOW_4BITS = 0x0F,

	TYPE_OF_ADDRESS_INTERNATIONAL_PHONE = 0x91,
	TYPE_OF_ADDRESS_NATIONAL_SUBSCRIBER = 0xC8,

	SMS_DELIVER_ONE_MESSAGE = 0x04,
	SMS_SUBMIT              = 0x11,

	SMS_MAX_7BIT_TEXT_LENGTH  = 160,
};

// Swap decimal digits of a number (e.g. 12 -> 21).
static unsigned char
SwapDecimalNibble(const unsigned char x)
{
	return (x / 16) + ((x % 16) * 10);
}



/*


*/

/** utf8_to_utf16.c */

#define UTF8_END   -1
#define UTF8_ERROR -2

typedef struct json_utf8_decode
{
    int the_index;
    char *the_input;
    int the_length;
    int the_char;
    int the_byte;
} json_utf8_decode;

extern int  utf8_decode_at_byte(json_utf8_decode *utf8);
extern int  utf8_decode_at_character(json_utf8_decode *utf8);
extern void utf8_decode_init(json_utf8_decode *utf8, char p[], int length);
extern int  utf8_decode_next(json_utf8_decode *utf8);

// utf8_to_utf16
extern int utf8_to_utf16(unsigned short w[], char p[], int length);

/**
    Very Strict UTF-8 Decoder

    UTF-8 is a multibyte character encoding of Unicode. A character can be
    represented by 1-4 bytes. The bit pattern of the first byte indicates the
    number of continuation bytes.

    Most UTF-8 decoders tend to be lenient, attempting to recover as much
    information as possible, even from badly encoded input. This UTF-8
    decoder is not lenient. It will reject input which does not include
    proper continuation bytes. It will reject aliases (or suboptimal
    codings). It will reject surrogates. (Surrogate encoding should only be
    used with UTF-16.)

    Code     Contination Minimum Maximum
    0xxxxxxx           0       0     127
    10xxxxxx       error
    110xxxxx           1     128    2047
    1110xxxx           2    2048   65535 excluding 55296 - 57343
    11110xxx           3   65536 1114111
    11111xxx       error
*/


/**
    Get the next byte. It returns UTF8_END if there are no more bytes.
*/
static int
get(json_utf8_decode *utf8)
{
    int c;
    if (utf8->the_index >= utf8->the_length) {
        return UTF8_END;
    }
    c = utf8->the_input[utf8->the_index] & 0xFF;
    utf8->the_index += 1;
    return c;
}


/**
    Get the 6-bit payload of the next continuation byte.
    Return UTF8_ERROR if it is not a contination byte.
*/
static int
cont(json_utf8_decode *utf8)
{
    int c = get(utf8);
    return ((c & 0xC0) == 0x80) ? (c & 0x3F) : UTF8_ERROR;
}


/**
    Initialize the UTF-8 decoder. The decoder is not reentrant,
*/
void
utf8_decode_init(json_utf8_decode *utf8, char p[], int length)
{
    utf8->the_index = 0;
    utf8->the_input = p;
    utf8->the_length = length;
    utf8->the_char = 0;
    utf8->the_byte = 0;
}


/**
    Get the current byte offset. This is generally used in error reporting.
*/
int
utf8_decode_at_byte(json_utf8_decode *utf8)
{
    return utf8->the_byte;
}


/**
    Get the current character offset. This is generally used in error reporting.
    The character offset matches the byte offset if the text is strictly ASCII.
*/
int
utf8_decode_at_character(json_utf8_decode *utf8)
{
    return utf8->the_char > 0 ? utf8->the_char - 1 : 0;
}


/**
    Extract the next character.
    Returns: the character (between 0 and 1114111)
         or  UTF8_END   (the end)
         or  UTF8_ERROR (error)
*/
int
utf8_decode_next(json_utf8_decode *utf8)
{
    int c;  /** the first byte of the character */
    int r;  /** the result */

    if (utf8->the_index >= utf8->the_length) {
        return utf8->the_index == utf8->the_length ? UTF8_END : UTF8_ERROR;
    }
    utf8->the_byte = utf8->the_index;
    utf8->the_char += 1;
    c = get(utf8);
/**
    Zero continuation (0 to 127)
*/
    if ((c & 0x80) == 0) {
        return c;
    }
/**
    One contination (128 to 2047)
*/
    if ((c & 0xE0) == 0xC0) {
        int c1 = cont(utf8);
        if (c1 < 0) {
            return UTF8_ERROR;
        }
        r = ((c & 0x1F) << 6) | c1;
        return r >= 128 ? r : UTF8_ERROR;
    }
/**
    Two continuation (2048 to 55295 and 57344 to 65535)
*/
    if ((c & 0xF0) == 0xE0) {
        int c1 = cont(utf8);
        int c2 = cont(utf8);
        if (c1 < 0 || c2 < 0) {
            return UTF8_ERROR;
        }
        r = ((c & 0x0F) << 12) | (c1 << 6) | c2;
        return r >= 2048 && (r < 55296 || r > 57343) ? r : UTF8_ERROR;
    }
/**
    Three continuation (65536 to 1114111)
*/
    if ((c & 0xF8) == 0xF0) {
        int c1 = cont(utf8);
        int c2 = cont(utf8);
        int c3 = cont(utf8);
        if (c1 < 0 || c2 < 0 || c3 < 0) {
            return UTF8_ERROR;
        }
        r = ((c & 0x0F) << 18) | (c1 << 12) | (c2 << 6) | c3;
        return r >= 65536 && r <= 1114111 ? r : UTF8_ERROR;
    }
    return UTF8_ERROR;
}

int utf8_to_utf16(unsigned short w[], char p[], int length)
{
    int c;
    int the_index = 0;
    json_utf8_decode utf8;
    utf8_decode_init(&utf8, p, length);
    for (;;) {
        c = utf8_decode_next(&utf8);
        if (c < 0) {
            return (c == UTF8_END) ? the_index : UTF8_ERROR;
        }
        if (c < 0x10000) {
            w[the_index] = (unsigned short)c;
            the_index += 1;
        } else {
            c -= 0x10000;
            w[the_index] = (unsigned short)(0xD800 | (c >> 10));
            the_index += 1;
            w[the_index] = (unsigned short)(0xDC00 | (c & 0x3FF));
            the_index += 1;
        }
    }

    return 0;

}

// Encode/Decode PDU: Translate ASCII 7bit characters to 8bit buffer.
// SMS encoding example from: http://www.dreamfabric.com/sms/.
//
// 7-bit ASCII: "hellohello"
// [0]:h   [1]:e   [2]:l   [3]:l   [4]:o   [5]:h   [6]:e   [7]:l   [8]:l   [9]:o
// 1101000 1100101 1101100 1101100 1101111 1101000 1100101 1101100 1101100 1101111
//               |             |||           ||||| |               |||||||  ||||||
// /-------------/   ///-------///     /////-///// \------------\  |||||||  \\\\\\ .
// |                 |||               |||||                    |  |||||||   ||||||
// input buffer position
// 10000000 22111111 33322222 44443333 55555333 66666655 77777776 98888888 --999999
// |                 |||               |||||                    |  |||||||   ||||||
// 8bit encoded buffer
// 11101000 00110010 10011011 11111101 01000110 10010111 11011001 11101100 00110111
// E8       32       9B       FD       46       97       D9       EC       37


// Encode PDU message by merging 7 bit ASCII characters into 8 bit octets.
static int
EncodePDUMessage(const char* sms_text, int sms_text_length, unsigned char* output_buffer, int buffer_size)
{
	// Check if output buffer is big enough.
	if ((sms_text_length * 7 + 7) / 8 > buffer_size)
		return -1;

	int output_buffer_length = 0;
	int carry_on_bits = 1;
	int i = 0;

	for (; i < sms_text_length - 1; ++i) {
		output_buffer[output_buffer_length++] =
			((sms_text[i] & BITMASK_7BITS) >> (carry_on_bits - 1)) |
			((sms_text[i + 1] & BITMASK_7BITS) << (8 - carry_on_bits));
		carry_on_bits++;
		if (carry_on_bits == 8) {
			carry_on_bits = 1;
			++i;
		}
	}

	if (i <= sms_text_length)
		output_buffer[output_buffer_length++] =	(sms_text[i] & BITMASK_7BITS) >> (carry_on_bits - 1);

	return output_buffer_length;
}



// Decode PDU message by splitting 8 bit encoded buffer into 7 bit ASCII
// characters.
static int
DecodePDUMessage_GSM_7bit(const unsigned char* buffer, int buffer_length, char* output_sms_text, int sms_text_length)
{
	int output_text_length = 0;
	if (buffer_length > 0)
		output_sms_text[output_text_length++] = BITMASK_7BITS & buffer[0];

	int carry_on_bits = 1;
	int i = 1;
	for (; i < buffer_length; ++i) {

		output_sms_text[output_text_length++] = BITMASK_7BITS &	((buffer[i] << carry_on_bits) | (buffer[i - 1] >> (8 - carry_on_bits)));

		if (output_text_length == sms_text_length) break;

		carry_on_bits++;

		if (carry_on_bits == 8) {
			carry_on_bits = 1;
			output_sms_text[output_text_length++] = buffer[i] & BITMASK_7BITS;
			if (output_text_length == sms_text_length) break;
		}

	}
	if (output_text_length < sms_text_length)  // Add last remainder.
		output_sms_text[output_text_length++] =	buffer[i - 1] >> (8 - carry_on_bits);

	return output_text_length;
}

// Encode a digit based phone number for SMS based format.
static int
EncodePhoneNumber(const char* phone_number, unsigned char* output_buffer, int buffer_size)
{
	int output_buffer_length = 0;
	const int phone_number_length = strlen(phone_number);

	// Check if the output buffer is big enough.
	if ((phone_number_length + 1) / 2 > buffer_size)
		return -1;

	int i = 0;
	for (; i < phone_number_length; ++i) {

		if (phone_number[i] < '0' && phone_number[i] > '9')
			return -1;

		if (i % 2 == 0) {
			output_buffer[output_buffer_length++] =	BITMASK_HIGH_4BITS | (phone_number[i] - '0');
		} else {
			output_buffer[output_buffer_length - 1] =
				(output_buffer[output_buffer_length - 1] & BITMASK_LOW_4BITS) |
				((phone_number[i] - '0') << 4);
		}
	}

	return output_buffer_length;
}

// Decode a digit based phone number for SMS based format.
static int
DecodePhoneNumber(const unsigned char* buffer, int phone_number_length, char* output_phone_number)
{
	int i = 0;
	for (; i < phone_number_length; ++i) {
		if (i % 2 == 0)
			output_phone_number[i] = (buffer[i / 2] & BITMASK_LOW_4BITS) + '0';
	        else
			output_phone_number[i] = ((buffer[i / 2] & BITMASK_HIGH_4BITS) >> 4) + '0';
	}
	output_phone_number[phone_number_length] = '\0';  // Terminate C string.
	return phone_number_length;
}



// Encode a SMS message to PDU
char * pdu_encode(const char* service_center_number, const char* phone_number, const char* sms_text, int buffer_size)
{

	unsigned char output_buffer[SMS_MAX_PDU_LENGTH];
	int i;
	char pdu[2*SMS_MAX_PDU_LENGTH+4];

	if (buffer_size < 2)
		return "NG";

	int output_buffer_length = 0;

	// 1. Set SMS center number.
	int length = 0;
	if (service_center_number && strlen(service_center_number) > 0) {
		output_buffer[1] = TYPE_OF_ADDRESS_INTERNATIONAL_PHONE;
		length = EncodePhoneNumber(service_center_number,
					   output_buffer + 2, buffer_size - 2);
		if (length < 0 && length >= 254)
			return "NG";
		length++;  // Add type of address.
	}
	output_buffer[0] = length;
	output_buffer_length = length + 1;
	if (output_buffer_length + 4 > buffer_size)
		return "NG";  // Check if it has space for four more bytes.
	// 2. Set type of message.
	output_buffer[output_buffer_length++] = SMS_SUBMIT;
	output_buffer[output_buffer_length++] = 0x00;  // Message reference.

	// 3. Set phone number.
	output_buffer[output_buffer_length] = strlen(phone_number);
	output_buffer[output_buffer_length + 1] = TYPE_OF_ADDRESS_INTERNATIONAL_PHONE;
	length = EncodePhoneNumber(phone_number,
				   output_buffer + output_buffer_length + 2,
				   buffer_size - output_buffer_length - 2);
	output_buffer_length += length + 2;
	if (output_buffer_length + 4 > buffer_size)
		return "NG"; // Check if it has space for four more bytes.

	// 4. Protocol identifiers.
	output_buffer[output_buffer_length++] = 0x00;  // TP-PID: Protocol identifier.
	output_buffer[output_buffer_length++] = 0x08;  // TP-DCS: Data coding scheme.  change to UCS2
	//output_buffer[output_buffer_length++] = 0xB0;  // TP-VP: Validity: 10 days
	output_buffer[output_buffer_length++] = 0x00;  // TP-VP: Validity: 10 days

	for (i = 0; i < output_buffer_length; ++i){
		sprintf(pdu+2*i, "%02X", output_buffer[i]);
	}

	int leni = 2*i;
	//长度预定为0
	pdu[leni] = '0';
	pdu[leni+1] = '0';

	// 5. SMS message.
//	char *text;
	char outtxt[100]={0};
	char outhex[200]={0};

	utf8_to_utf16((unsigned short *)outtxt,(char *) sms_text,strlen(sms_text));

	debug(LOG_DEBUG,"utf8_to_utf16\r\n");

	for (i = 0;outtxt[2*i]!='\0' ;i++)
	{
		char a[10]={0};
		char b[10]={0};
//		char a1[10]={0};
//		char a2[10]={0};

		sprintf(a,"%02X",outtxt[2*i+1]);
		sprintf(b,"%02X",outtxt[2*i]);

		if(strlen(a) ==8){
			sprintf(a,"%c%c",a[6],a[7]);
		}
		if(strlen(b) ==8){
			sprintf(b,"%c%c",b[6],b[7]);
		}
		sprintf(outhex+4*i,"%s%s",a,b);

	}

	sprintf(pdu+leni,"%02X", strlen(outhex)/2);
	pdu[leni+2] = '\0';
	char *res;
	safe_asprintf(&res,"%s%s",(char *)pdu,(char *)outhex);
	debug(LOG_DEBUG,"\r\n over res[%s]\r\n",res);
	return res;
}

int pdu_decode(const unsigned char* buffer, int buffer_length,
	       time_t* output_sms_time,
	       char* output_sender_phone_number, int sender_phone_number_size,
	       char* output_sms_text, int sms_text_size,
	       int* tp_dcs,
	       int* user_payload_header_size)
{

	if (buffer_length <= 0)
		return -1;


	const int sms_deliver_start = 1 + buffer[0];
	if (sms_deliver_start + 1 > buffer_length)
		return -2;

	const int user_data_header_length = (buffer[sms_deliver_start]>>4);

	*user_payload_header_size = user_data_header_length;

	const int sender_number_length = buffer[sms_deliver_start + 1];
	if (sender_number_length + 1 > sender_phone_number_size)
		return -3;  // Buffer too small to hold decoded phone number.

	// const int sender_type_of_address = buffer[sms_deliver_start + 2];
	DecodePhoneNumber(buffer + sms_deliver_start + 3, sender_number_length,  output_sender_phone_number);

	const int sms_pid_start = sms_deliver_start + 3 + (buffer[sms_deliver_start + 1] + 1) / 2;

	// Decode timestamp.
	struct tm sms_broken_time;
	sms_broken_time.tm_year = 100 + SwapDecimalNibble(buffer[sms_pid_start + 2]);
	sms_broken_time.tm_mon  = SwapDecimalNibble(buffer[sms_pid_start + 3]) - 1;
	sms_broken_time.tm_mday = SwapDecimalNibble(buffer[sms_pid_start + 4]);
	sms_broken_time.tm_hour = SwapDecimalNibble(buffer[sms_pid_start + 5]);
	sms_broken_time.tm_min  = SwapDecimalNibble(buffer[sms_pid_start + 6]);
	sms_broken_time.tm_sec  = SwapDecimalNibble(buffer[sms_pid_start + 7]);
	const char gmt_offset   = SwapDecimalNibble(buffer[sms_pid_start + 8]);
	// GMT offset is expressed in 15 minutes increments.
	(*output_sms_time) = mktime(&sms_broken_time) - gmt_offset * 15 * 60;

	const int sms_start = sms_pid_start + 2 + 7;
	if (sms_start + 1 > buffer_length) return -1;  // Invalid input buffer.

	const int output_sms_text_length = buffer[sms_start];
	if (sms_text_size < output_sms_text_length) return -1;  // Cannot hold decoded buffer.

	const int sms_tp_dcs_start = sms_pid_start + 1;
	*tp_dcs = buffer[sms_tp_dcs_start];

	switch(*tp_dcs)
	{
		case 0:
			{
				int decoded_sms_text_size = DecodePDUMessage_GSM_7bit(buffer + sms_start + 1, buffer_length - (sms_start + 1),
							   output_sms_text, output_sms_text_length);
				if (decoded_sms_text_size != output_sms_text_length) return -1;  // Decoder length is not as expected.
				break;
			}
		case 8:
			{
				memcpy(output_sms_text, buffer + sms_start + 1, output_sms_text_length);
				break;
			}
		default:
		break;
	}

	// Add a C string end.
	if (output_sms_text_length < sms_text_size)
		output_sms_text[output_sms_text_length] = 0;
	else
		output_sms_text[sms_text_size-1] = 0;

	return output_sms_text_length;
}
