/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <pgmspace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "bearssl/bearssl.h"

static const char _NAME_BR_ERR_BAD_PARAM[] PROGMEM = "BR_ERR_BAD_PARAM";
static const char _DESC_BR_ERR_BAD_PARAM[] PROGMEM = "Caller-provided parameter is incorrect.";
static const char _NAME_BR_ERR_BAD_STATE[] PROGMEM = "BR_ERR_BAD_STATE";
static const char _DESC_BR_ERR_BAD_STATE[] PROGMEM = "Operation requested by the caller cannot be applied with the current context state (e.g. reading data while outgoing data is waiting to be sent).";
static const char _NAME_BR_ERR_UNSUPPORTED_VERSION[] PROGMEM = "BR_ERR_UNSUPPORTED_VERSION";
static const char _DESC_BR_ERR_UNSUPPORTED_VERSION[] PROGMEM = "Incoming protocol or record version is unsupported.";
static const char _NAME_BR_ERR_BAD_VERSION[] PROGMEM = "BR_ERR_BAD_VERSION";
static const char _DESC_BR_ERR_BAD_VERSION[] PROGMEM = "Incoming record version does not match the expected version.";
static const char _NAME_BR_ERR_BAD_LENGTH[] PROGMEM = "BR_ERR_BAD_LENGTH";
static const char _DESC_BR_ERR_BAD_LENGTH[] PROGMEM = "Incoming record length is invalid.";
static const char _NAME_BR_ERR_TOO_LARGE[] PROGMEM = "BR_ERR_TOO_LARGE";
static const char _DESC_BR_ERR_TOO_LARGE[] PROGMEM = "Incoming record is too large to be processed, or buffer is too small for the handshake message to send.";
static const char _NAME_BR_ERR_BAD_MAC[] PROGMEM = "BR_ERR_BAD_MAC";
static const char _DESC_BR_ERR_BAD_MAC[] PROGMEM = "Decryption found an invalid padding, or the record MAC is not correct.";
static const char _NAME_BR_ERR_NO_RANDOM[] PROGMEM = "BR_ERR_NO_RANDOM";
static const char _DESC_BR_ERR_NO_RANDOM[] PROGMEM = "No initial entropy was provided, and none can be obtained from the OS.";
static const char _NAME_BR_ERR_UNKNOWN_TYPE[] PROGMEM = "BR_ERR_UNKNOWN_TYPE";
static const char _DESC_BR_ERR_UNKNOWN_TYPE[] PROGMEM = "Incoming record type is unknown.";
static const char _NAME_BR_ERR_UNEXPECTED[] PROGMEM = "BR_ERR_UNEXPECTED";
static const char _DESC_BR_ERR_UNEXPECTED[] PROGMEM = "Incoming record or message has wrong type with regards to the current engine state.";
static const char _NAME_BR_ERR_BAD_CCS[] PROGMEM = "BR_ERR_BAD_CCS";
static const char _DESC_BR_ERR_BAD_CCS[] PROGMEM = "ChangeCipherSpec message from the peer has invalid contents.";
static const char _NAME_BR_ERR_BAD_ALERT[] PROGMEM = "BR_ERR_BAD_ALERT";
static const char _DESC_BR_ERR_BAD_ALERT[] PROGMEM = "Alert message from the peer has invalid contents (odd length).";
static const char _NAME_BR_ERR_BAD_HANDSHAKE[] PROGMEM = "BR_ERR_BAD_HANDSHAKE";
static const char _DESC_BR_ERR_BAD_HANDSHAKE[] PROGMEM = "Incoming handshake message decoding failed.";
static const char _NAME_BR_ERR_OVERSIZED_ID[] PROGMEM = "BR_ERR_OVERSIZED_ID";
static const char _DESC_BR_ERR_OVERSIZED_ID[] PROGMEM = "ServerHello contains a session ID which is larger than 32 bytes.";
static const char _NAME_BR_ERR_BAD_CIPHER_SUITE[] PROGMEM = "BR_ERR_BAD_CIPHER_SUITE";
static const char _DESC_BR_ERR_BAD_CIPHER_SUITE[] PROGMEM = "Server wants to use a cipher suite that we did not claim to support. This is also reported if we tried to advertise a cipher suite that we do not support.";
static const char _NAME_BR_ERR_BAD_COMPRESSION[] PROGMEM = "BR_ERR_BAD_COMPRESSION";
static const char _DESC_BR_ERR_BAD_COMPRESSION[] PROGMEM = "Server wants to use a compression that we did not claim to support.";
static const char _NAME_BR_ERR_BAD_FRAGLEN[] PROGMEM = "BR_ERR_BAD_FRAGLEN";
static const char _DESC_BR_ERR_BAD_FRAGLEN[] PROGMEM = "Server's max fragment length does not match client's.";
static const char _NAME_BR_ERR_BAD_SECRENEG[] PROGMEM = "BR_ERR_BAD_SECRENEG";
static const char _DESC_BR_ERR_BAD_SECRENEG[] PROGMEM = "Secure renegotiation failed.";
static const char _NAME_BR_ERR_EXTRA_EXTENSION[] PROGMEM = "BR_ERR_EXTRA_EXTENSION";
static const char _DESC_BR_ERR_EXTRA_EXTENSION[] PROGMEM = "Server sent an extension type that we did not announce, or used the same extension type several times in a single ServerHello.";
static const char _NAME_BR_ERR_BAD_SNI[] PROGMEM = "BR_ERR_BAD_SNI";
static const char _DESC_BR_ERR_BAD_SNI[] PROGMEM = "Invalid Server Name Indication contents (when used by the server, this extension shall be empty).";
static const char _NAME_BR_ERR_BAD_HELLO_DONE[] PROGMEM = "BR_ERR_BAD_HELLO_DONE";
static const char _DESC_BR_ERR_BAD_HELLO_DONE[] PROGMEM = "Invalid ServerHelloDone from the server (length is not 0).";
static const char _NAME_BR_ERR_LIMIT_EXCEEDED[] PROGMEM = "BR_ERR_LIMIT_EXCEEDED";
static const char _DESC_BR_ERR_LIMIT_EXCEEDED[] PROGMEM = "Internal limit exceeded (e.g. server's public key is too large).";
static const char _NAME_BR_ERR_BAD_FINISHED[] PROGMEM = "BR_ERR_BAD_FINISHED";
static const char _DESC_BR_ERR_BAD_FINISHED[] PROGMEM = "Finished message from peer does not match the expected value.";
static const char _NAME_BR_ERR_RESUME_MISMATCH[] PROGMEM = "BR_ERR_RESUME_MISMATCH";
static const char _DESC_BR_ERR_RESUME_MISMATCH[] PROGMEM = "Session resumption attempt with distinct version or cipher suite.";
static const char _NAME_BR_ERR_INVALID_ALGORITHM[] PROGMEM = "BR_ERR_INVALID_ALGORITHM";
static const char _DESC_BR_ERR_INVALID_ALGORITHM[] PROGMEM = "Unsupported or invalid algorithm (ECDHE curve, signature algorithm, hash function).";
static const char _NAME_BR_ERR_BAD_SIGNATURE[] PROGMEM = "BR_ERR_BAD_SIGNATURE";
static const char _DESC_BR_ERR_BAD_SIGNATURE[] PROGMEM = "Invalid signature in ServerKeyExchange or CertificateVerify message.";
static const char _NAME_BR_ERR_WRONG_KEY_USAGE[] PROGMEM = "BR_ERR_WRONG_KEY_USAGE";
static const char _DESC_BR_ERR_WRONG_KEY_USAGE[] PROGMEM = "Peer's public key does not have the proper type or is not allowed for the requested operation.";
static const char _NAME_BR_ERR_NO_CLIENT_AUTH[] PROGMEM = "BR_ERR_NO_CLIENT_AUTH";
static const char _DESC_BR_ERR_NO_CLIENT_AUTH[] PROGMEM = "Client did not send a certificate upon request, or the client certificate could not be validated.";
static const char _NAME_BR_ERR_IO[] PROGMEM = "BR_ERR_IO";
static const char _DESC_BR_ERR_IO[] PROGMEM = "I/O error or premature close on transport stream.";
static const char _NAME_BR_ERR_X509_INVALID_VALUE[] PROGMEM = "BR_ERR_X509_INVALID_VALUE";
static const char _DESC_BR_ERR_X509_INVALID_VALUE[] PROGMEM = "Invalid value in an ASN.1 structure.";
static const char _NAME_BR_ERR_X509_TRUNCATED[] PROGMEM = "BR_ERR_X509_TRUNCATED";
static const char _DESC_BR_ERR_X509_TRUNCATED[] PROGMEM = "Truncated certificate or other ASN.1 object.";
static const char _NAME_BR_ERR_X509_EMPTY_CHAIN[] PROGMEM = "BR_ERR_X509_EMPTY_CHAIN";
static const char _DESC_BR_ERR_X509_EMPTY_CHAIN[] PROGMEM = "Empty certificate chain (no certificate at all).";
static const char _NAME_BR_ERR_X509_INNER_TRUNC[] PROGMEM = "BR_ERR_X509_INNER_TRUNC";
static const char _DESC_BR_ERR_X509_INNER_TRUNC[] PROGMEM = "Decoding error: inner element extends beyond outer element size.";
static const char _NAME_BR_ERR_X509_BAD_TAG_CLASS[] PROGMEM = "BR_ERR_X509_BAD_TAG_CLASS";
static const char _DESC_BR_ERR_X509_BAD_TAG_CLASS[] PROGMEM = "Decoding error: unsupported tag class (application or private).";
static const char _NAME_BR_ERR_X509_BAD_TAG_VALUE[] PROGMEM = "BR_ERR_X509_BAD_TAG_VALUE";
static const char _DESC_BR_ERR_X509_BAD_TAG_VALUE[] PROGMEM = "Decoding error: unsupported tag value.";
static const char _NAME_BR_ERR_X509_INDEFINITE_LENGTH[] PROGMEM = "BR_ERR_X509_INDEFINITE_LENGTH";
static const char _DESC_BR_ERR_X509_INDEFINITE_LENGTH[] PROGMEM = "Decoding error: indefinite length.";
static const char _NAME_BR_ERR_X509_EXTRA_ELEMENT[] PROGMEM = "BR_ERR_X509_EXTRA_ELEMENT";
static const char _DESC_BR_ERR_X509_EXTRA_ELEMENT[] PROGMEM = "Decoding error: extraneous element.";
static const char _NAME_BR_ERR_X509_UNEXPECTED[] PROGMEM = "BR_ERR_X509_UNEXPECTED";
static const char _DESC_BR_ERR_X509_UNEXPECTED[] PROGMEM = "Decoding error: unexpected element.";
static const char _NAME_BR_ERR_X509_NOT_CONSTRUCTED[] PROGMEM = "BR_ERR_X509_NOT_CONSTRUCTED";
static const char _DESC_BR_ERR_X509_NOT_CONSTRUCTED[] PROGMEM = "Decoding error: expected constructed element, but is primitive.";
static const char _NAME_BR_ERR_X509_NOT_PRIMITIVE[] PROGMEM = "BR_ERR_X509_NOT_PRIMITIVE";
static const char _DESC_BR_ERR_X509_NOT_PRIMITIVE[] PROGMEM = "Decoding error: expected primitive element, but is constructed.";
static const char _NAME_BR_ERR_X509_PARTIAL_BYTE[] PROGMEM = "BR_ERR_X509_PARTIAL_BYTE";
static const char _DESC_BR_ERR_X509_PARTIAL_BYTE[] PROGMEM = "Decoding error: BIT STRING length is not multiple of 8.";
static const char _NAME_BR_ERR_X509_BAD_BOOLEAN[] PROGMEM = "BR_ERR_X509_BAD_BOOLEAN";
static const char _DESC_BR_ERR_X509_BAD_BOOLEAN[] PROGMEM = "Decoding error: BOOLEAN value has invalid length.";
static const char _NAME_BR_ERR_X509_OVERFLOW[] PROGMEM = "BR_ERR_X509_OVERFLOW";
static const char _DESC_BR_ERR_X509_OVERFLOW[] PROGMEM = "Decoding error: value is off-limits.";
static const char _NAME_BR_ERR_X509_BAD_DN[] PROGMEM = "BR_ERR_X509_BAD_DN";
static const char _DESC_BR_ERR_X509_BAD_DN[] PROGMEM = "Invalid distinguished name.";
static const char _NAME_BR_ERR_X509_BAD_TIME[] PROGMEM = "BR_ERR_X509_BAD_TIME";
static const char _DESC_BR_ERR_X509_BAD_TIME[] PROGMEM = "Invalid date/time representation.";
static const char _NAME_BR_ERR_X509_UNSUPPORTED[] PROGMEM = "BR_ERR_X509_UNSUPPORTED";
static const char _DESC_BR_ERR_X509_UNSUPPORTED[] PROGMEM = "Certificate contains unsupported features that cannot be ignored.";
static const char _NAME_BR_ERR_X509_LIMIT_EXCEEDED[] PROGMEM = "BR_ERR_X509_LIMIT_EXCEEDED";
static const char _DESC_BR_ERR_X509_LIMIT_EXCEEDED[] PROGMEM = "Key or signature size exceeds internal limits.";
static const char _NAME_BR_ERR_X509_WRONG_KEY_TYPE[] PROGMEM = "BR_ERR_X509_WRONG_KEY_TYPE";
static const char _DESC_BR_ERR_X509_WRONG_KEY_TYPE[] PROGMEM = "Key type does not match that which was expected.";
static const char _NAME_BR_ERR_X509_BAD_SIGNATURE[] PROGMEM = "BR_ERR_X509_BAD_SIGNATURE";
static const char _DESC_BR_ERR_X509_BAD_SIGNATURE[] PROGMEM = "Signature is invalid.";
static const char _NAME_BR_ERR_X509_TIME_UNKNOWN[] PROGMEM = "BR_ERR_X509_TIME_UNKNOWN";
static const char _DESC_BR_ERR_X509_TIME_UNKNOWN[] PROGMEM = "Validation time is unknown.";
static const char _NAME_BR_ERR_X509_EXPIRED[] PROGMEM = "BR_ERR_X509_EXPIRED";
static const char _DESC_BR_ERR_X509_EXPIRED[] PROGMEM = "Certificate is expired or not yet valid.";
static const char _NAME_BR_ERR_X509_DN_MISMATCH[] PROGMEM = "BR_ERR_X509_DN_MISMATCH";
static const char _DESC_BR_ERR_X509_DN_MISMATCH[] PROGMEM = "Issuer/Subject DN mismatch in the chain.";
static const char _NAME_BR_ERR_X509_BAD_SERVER_NAME[] PROGMEM = "BR_ERR_X509_BAD_SERVER_NAME";
static const char _DESC_BR_ERR_X509_BAD_SERVER_NAME[] PROGMEM = "Expected server name was not found in the chain.";
static const char _NAME_BR_ERR_X509_CRITICAL_EXTENSION[] PROGMEM = "BR_ERR_X509_CRITICAL_EXTENSION";
static const char _DESC_BR_ERR_X509_CRITICAL_EXTENSION[] PROGMEM = "Unknown critical extension in certificate.";
static const char _NAME_BR_ERR_X509_NOT_CA[] PROGMEM = "BR_ERR_X509_NOT_CA";
static const char _DESC_BR_ERR_X509_NOT_CA[] PROGMEM = "Not a CA, or path length constraint violation.";
static const char _NAME_BR_ERR_X509_FORBIDDEN_KEY_USAGE[] PROGMEM = "BR_ERR_X509_FORBIDDEN_KEY_USAGE";
static const char _DESC_BR_ERR_X509_FORBIDDEN_KEY_USAGE[] PROGMEM = "Key Usage extension prohibits intended usage.";
static const char _NAME_BR_ERR_X509_WEAK_PUBLIC_KEY[] PROGMEM = "BR_ERR_X509_WEAK_PUBLIC_KEY";
static const char _DESC_BR_ERR_X509_WEAK_PUBLIC_KEY[] PROGMEM = "Public key found in certificate is too small.";
static const char _NAME_BR_ERR_X509_NOT_TRUSTED[] PROGMEM = "BR_ERR_X509_NOT_TRUSTED";
static const char _DESC_BR_ERR_X509_NOT_TRUSTED[] PROGMEM = "Chain could not be linked to a trust anchor.";

static struct {
    int err;
    const char *name;
    const char *comment;
} errors[] = {
    {
        BR_ERR_BAD_PARAM,
        _NAME_BR_ERR_BAD_PARAM,
        _DESC_BR_ERR_BAD_PARAM
    }, {
        BR_ERR_BAD_STATE,
        _NAME_BR_ERR_BAD_STATE,
        _DESC_BR_ERR_BAD_STATE
    }, {
        BR_ERR_UNSUPPORTED_VERSION,
        _NAME_BR_ERR_UNSUPPORTED_VERSION,
        _DESC_BR_ERR_UNSUPPORTED_VERSION
    }, {
        BR_ERR_BAD_VERSION,
        _NAME_BR_ERR_BAD_VERSION,
        _DESC_BR_ERR_BAD_VERSION
    }, {
        BR_ERR_BAD_LENGTH,
        _NAME_BR_ERR_BAD_LENGTH,
        _DESC_BR_ERR_BAD_LENGTH
    }, {
        BR_ERR_TOO_LARGE,
        _NAME_BR_ERR_TOO_LARGE,
        _DESC_BR_ERR_TOO_LARGE
    }, {
        BR_ERR_BAD_MAC,
        _NAME_BR_ERR_BAD_MAC,
        _DESC_BR_ERR_BAD_MAC
    }, {
        BR_ERR_NO_RANDOM,
        _NAME_BR_ERR_NO_RANDOM,
        _DESC_BR_ERR_NO_RANDOM
    }, {
        BR_ERR_UNKNOWN_TYPE,
        _NAME_BR_ERR_UNKNOWN_TYPE,
        _DESC_BR_ERR_UNKNOWN_TYPE
    }, {
        BR_ERR_UNEXPECTED,
        _NAME_BR_ERR_UNEXPECTED,
        _DESC_BR_ERR_UNEXPECTED
    }, {
        BR_ERR_BAD_CCS,
        _NAME_BR_ERR_BAD_CCS,
        _DESC_BR_ERR_BAD_CCS
    }, {
        BR_ERR_BAD_ALERT,
        _NAME_BR_ERR_BAD_ALERT,
        _DESC_BR_ERR_BAD_ALERT
    }, {
        BR_ERR_BAD_HANDSHAKE,
        _NAME_BR_ERR_BAD_HANDSHAKE,
        _DESC_BR_ERR_BAD_HANDSHAKE
    }, {
        BR_ERR_OVERSIZED_ID,
        _NAME_BR_ERR_OVERSIZED_ID,
        _DESC_BR_ERR_OVERSIZED_ID
    }, {
        BR_ERR_BAD_CIPHER_SUITE,
        _NAME_BR_ERR_BAD_CIPHER_SUITE,
        _DESC_BR_ERR_BAD_CIPHER_SUITE
    }, {
        BR_ERR_BAD_COMPRESSION,
        _NAME_BR_ERR_BAD_COMPRESSION,
        _DESC_BR_ERR_BAD_COMPRESSION
    }, {
        BR_ERR_BAD_FRAGLEN,
        _NAME_BR_ERR_BAD_FRAGLEN,
        _DESC_BR_ERR_BAD_FRAGLEN
    }, {
        BR_ERR_BAD_SECRENEG,
        _NAME_BR_ERR_BAD_SECRENEG,
        _DESC_BR_ERR_BAD_SECRENEG
    }, {
        BR_ERR_EXTRA_EXTENSION,
        _NAME_BR_ERR_EXTRA_EXTENSION,
        _DESC_BR_ERR_EXTRA_EXTENSION
    }, {
        BR_ERR_BAD_SNI,
        _NAME_BR_ERR_BAD_SNI,
        _DESC_BR_ERR_BAD_SNI
    }, {
        BR_ERR_BAD_HELLO_DONE,
        _NAME_BR_ERR_BAD_HELLO_DONE,
        _DESC_BR_ERR_BAD_HELLO_DONE
    }, {
        BR_ERR_LIMIT_EXCEEDED,
        _NAME_BR_ERR_LIMIT_EXCEEDED,
        _DESC_BR_ERR_LIMIT_EXCEEDED
    }, {
        BR_ERR_BAD_FINISHED,
        _NAME_BR_ERR_BAD_FINISHED,
        _DESC_BR_ERR_BAD_FINISHED
    }, {
        BR_ERR_RESUME_MISMATCH,
        _NAME_BR_ERR_RESUME_MISMATCH,
        _DESC_BR_ERR_RESUME_MISMATCH
    }, {
        BR_ERR_INVALID_ALGORITHM,
        _NAME_BR_ERR_INVALID_ALGORITHM,
        _DESC_BR_ERR_INVALID_ALGORITHM
    }, {
        BR_ERR_BAD_SIGNATURE,
        _NAME_BR_ERR_BAD_SIGNATURE,
        _DESC_BR_ERR_BAD_SIGNATURE
    }, {
        BR_ERR_WRONG_KEY_USAGE,
        _NAME_BR_ERR_WRONG_KEY_USAGE,
        _DESC_BR_ERR_WRONG_KEY_USAGE
    }, {
        BR_ERR_NO_CLIENT_AUTH,
        _NAME_BR_ERR_NO_CLIENT_AUTH,
        _DESC_BR_ERR_NO_CLIENT_AUTH
    }, {
        BR_ERR_IO,
        _NAME_BR_ERR_IO,
        _DESC_BR_ERR_IO
    }, {
        BR_ERR_X509_INVALID_VALUE,
        _NAME_BR_ERR_X509_INVALID_VALUE,
        _DESC_BR_ERR_X509_INVALID_VALUE
    },
    {
        BR_ERR_X509_TRUNCATED,
        _NAME_BR_ERR_X509_TRUNCATED,
        _DESC_BR_ERR_X509_TRUNCATED
    },
    {
        BR_ERR_X509_EMPTY_CHAIN,
        _NAME_BR_ERR_X509_EMPTY_CHAIN,
        _DESC_BR_ERR_X509_EMPTY_CHAIN
    },
    {
        BR_ERR_X509_INNER_TRUNC,
        _NAME_BR_ERR_X509_INNER_TRUNC,
        _DESC_BR_ERR_X509_INNER_TRUNC
    },
    {
        BR_ERR_X509_BAD_TAG_CLASS,
        _NAME_BR_ERR_X509_BAD_TAG_CLASS,
        _DESC_BR_ERR_X509_BAD_TAG_CLASS
    },
    {
        BR_ERR_X509_BAD_TAG_VALUE,
        _NAME_BR_ERR_X509_BAD_TAG_VALUE,
        _DESC_BR_ERR_X509_BAD_TAG_VALUE
    },
    {
        BR_ERR_X509_INDEFINITE_LENGTH,
        _NAME_BR_ERR_X509_INDEFINITE_LENGTH,
        _DESC_BR_ERR_X509_INDEFINITE_LENGTH
    },
    {
        BR_ERR_X509_EXTRA_ELEMENT,
        _NAME_BR_ERR_X509_EXTRA_ELEMENT,
        _DESC_BR_ERR_X509_EXTRA_ELEMENT
    },
    {
        BR_ERR_X509_UNEXPECTED,
        _NAME_BR_ERR_X509_UNEXPECTED,
        _DESC_BR_ERR_X509_UNEXPECTED
    },
    {
        BR_ERR_X509_NOT_CONSTRUCTED,
        _NAME_BR_ERR_X509_NOT_CONSTRUCTED,
        _DESC_BR_ERR_X509_NOT_CONSTRUCTED
    },
    {
        BR_ERR_X509_NOT_PRIMITIVE,
        _NAME_BR_ERR_X509_NOT_PRIMITIVE,
        _DESC_BR_ERR_X509_NOT_PRIMITIVE
    },
    {
        BR_ERR_X509_PARTIAL_BYTE,
        _NAME_BR_ERR_X509_PARTIAL_BYTE,
        _DESC_BR_ERR_X509_PARTIAL_BYTE
    },
    {
        BR_ERR_X509_BAD_BOOLEAN,
        _NAME_BR_ERR_X509_BAD_BOOLEAN,
        _DESC_BR_ERR_X509_BAD_BOOLEAN
    },
    {
        BR_ERR_X509_OVERFLOW,
        _NAME_BR_ERR_X509_OVERFLOW,
        _DESC_BR_ERR_X509_OVERFLOW
    },
    {
        BR_ERR_X509_BAD_DN,
        _NAME_BR_ERR_X509_BAD_DN,
        _DESC_BR_ERR_X509_BAD_DN
    },
    {
        BR_ERR_X509_BAD_TIME,
        _NAME_BR_ERR_X509_BAD_TIME,
        _DESC_BR_ERR_X509_BAD_TIME
    },
    {
        BR_ERR_X509_UNSUPPORTED,
        _NAME_BR_ERR_X509_UNSUPPORTED,
        _DESC_BR_ERR_X509_UNSUPPORTED
    },
    {
        BR_ERR_X509_LIMIT_EXCEEDED,
        _NAME_BR_ERR_X509_LIMIT_EXCEEDED,
        _DESC_BR_ERR_X509_LIMIT_EXCEEDED
    },
    {
        BR_ERR_X509_WRONG_KEY_TYPE,
        _NAME_BR_ERR_X509_WRONG_KEY_TYPE,
        _DESC_BR_ERR_X509_WRONG_KEY_TYPE
    },
    {
        BR_ERR_X509_BAD_SIGNATURE,
        _NAME_BR_ERR_X509_BAD_SIGNATURE,
        _DESC_BR_ERR_X509_BAD_SIGNATURE
    },
    {
        BR_ERR_X509_TIME_UNKNOWN,
        _NAME_BR_ERR_X509_TIME_UNKNOWN,
        _DESC_BR_ERR_X509_TIME_UNKNOWN
    },
    {
        BR_ERR_X509_EXPIRED,
        _NAME_BR_ERR_X509_EXPIRED,
        _DESC_BR_ERR_X509_EXPIRED
    },
    {
        BR_ERR_X509_DN_MISMATCH,
        _NAME_BR_ERR_X509_DN_MISMATCH,
        _DESC_BR_ERR_X509_DN_MISMATCH
    },
    {
        BR_ERR_X509_BAD_SERVER_NAME,
        _NAME_BR_ERR_X509_BAD_SERVER_NAME,
        _DESC_BR_ERR_X509_BAD_SERVER_NAME
    },
    {
        BR_ERR_X509_CRITICAL_EXTENSION,
        _NAME_BR_ERR_X509_CRITICAL_EXTENSION,
        _DESC_BR_ERR_X509_CRITICAL_EXTENSION
    },
    {
        BR_ERR_X509_NOT_CA,
        _NAME_BR_ERR_X509_NOT_CA,
        _DESC_BR_ERR_X509_NOT_CA
    },
    {
        BR_ERR_X509_FORBIDDEN_KEY_USAGE,
        _NAME_BR_ERR_X509_FORBIDDEN_KEY_USAGE,
        _DESC_BR_ERR_X509_FORBIDDEN_KEY_USAGE
    },
    {
        BR_ERR_X509_WEAK_PUBLIC_KEY,
        _NAME_BR_ERR_X509_WEAK_PUBLIC_KEY,
        _DESC_BR_ERR_X509_WEAK_PUBLIC_KEY
    },
    {
        BR_ERR_X509_NOT_TRUSTED,
        _NAME_BR_ERR_X509_NOT_TRUSTED,
        _DESC_BR_ERR_X509_NOT_TRUSTED
    },
    { 0, 0, 0 }
};

/* see brssl.h */
const char *
find_error_name(int err, const char **comment)
{
    size_t u;

    for (u = 0; errors[u].name; u++) {
        if (errors[u].err == err) {
            if (comment != NULL) {
                *comment = errors[u].comment;
            }
            return errors[u].name;
        }
    }
    return NULL;
}
