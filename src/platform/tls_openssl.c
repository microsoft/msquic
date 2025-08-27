/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS functions by calling OpenSSL.

--*/
#include "platform_internal.h"

#include "openssl/opensslv.h"
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100) // Unreferenced parameter errcode in inline function
#endif
#include "openssl/bio.h"
#include "openssl/core_names.h"
#include "openssl/err.h"
#include "openssl/kdf.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/pkcs7.h"
#include "openssl/rsa.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#ifdef _WIN32
#pragma warning(pop)
#endif
#ifdef QUIC_CLOG
#include "tls_openssl.c.clog.h"
#endif

 //
 // @struct CXPLAT_SEC_CONFIG
 // @brief Represents the security configuration used for TLS.
 // 
 // This structure encapsulates all the necessary information for
 // configuring TLS security settings, including SSL context,
 // ticket keying, and callback functions.
 // 
typedef struct CXPLAT_SEC_CONFIG {

    //
    // SSL context used for establishing TLS connections.
    //
    SSL_CTX *SSLCtx;

    //
    // Pointer to the ticket key configuration for session resumption.
    //
    QUIC_TICKET_KEY_CONFIG* TicketKey;

    //
    // TLS-related callbacks for handling crypto events.
    //
    CXPLAT_TLS_CALLBACKS Callbacks;

    //
    // Credential flags specifying various QUIC credential options.
    //
    QUIC_CREDENTIAL_FLAGS Flags;

    //
    // Flags that specify behavior for TLS credential handling.
    //
    CXPLAT_TLS_CREDENTIAL_FLAGS TlsFlags;

} CXPLAT_SEC_CONFIG;

//
// @struct CXPLAT_TLS
// @brief Represents the state and configuration of a TLS session.
//
// This structure holds information necessary to manage a TLS handshake,
// encryption state, and associated connection details for QUIC.
//
typedef struct CXPLAT_TLS {

    //
    // Pointer to the security configuration used for the TLS session.
    //
    CXPLAT_SEC_CONFIG* SecConfig;

    //
    // Pointer to HKDF label definitions used in the key derivation process.
    //
    const QUIC_HKDF_LABELS* HkdfLabels;

    //
    // Indicates if the endpoint is acting as a server.
    //
    BOOLEAN IsServer : 1;

    //
    // Indicates if a peer certificate has been received.
    //
    BOOLEAN PeerCertReceived : 1;

    //
    // Indicates if the peer's transport parameters have been received.
    //
    BOOLEAN PeerTPReceived : 1;

    //
    // QUIC transport parameter extension type used in the session.
    //
    uint16_t QuicTpExtType;

    //
    // Length of the ALPN buffer.
    //
    uint16_t AlpnBufferLength;

    //
    // Pointer to the ALPN buffer data.
    //
    const uint8_t* AlpnBuffer;

    //
    // Pointer to the Server Name Indication (SNI) string.
    //
    const char* SNI;

    //
    // OpenSSL SSL object used for the TLS handshake and encryption.
    //
    SSL *Ssl;

    //
    // Pointer to internal TLS processing state.
    //
    CXPLAT_TLS_PROCESS_STATE* State;

    //
    // Flags indicating the results of TLS processing.
    //
    CXPLAT_TLS_RESULT_FLAGS ResultFlags;

    //
    // Pointer to the QUIC connection associated with this TLS session.
    //
    QUIC_CONNECTION* Connection;

    //
    // Pointer to derived TLS secrets for encryption and decryption.
    //
    QUIC_TLS_SECRETS* TlsSecrets;

} CXPLAT_TLS;

//
// @struct RECORD_ENTRY
// @brief Represents a buffered SSL record in a linked list.
//
// This structure is used to store an SSL record along with its
// metAData and linkage in a list. It supports tracking incomplete
// records and whether the memory should be freed.
//
typedef struct RECORD_ENTRY {
    //
    // Linked list node for linking Entries in a list.
    //
    CXPLAT_LIST_ENTRY Link;

    //
    // Length of the SSL record.
    //
    size_t RecLen;

    //
    // Pointer to the associated SSL connection.
    //
    SSL *Ssl;

    //
    // Non-zero if the record is incomplete.
    //
    unsigned char Incomplete;

    //
    // Non-zero if the record memory should be freed.
    //
    unsigned char FreeMe;

    //
    // The raw SSL record data.
    //
    uint8_t Record[0];
} RECORD_ENTRY;

typedef struct SECRET_SET {
    uint8_t *Secret;
    size_t SecretLen;
    uint8_t installed;
} SECRET_SET;

//
// @struct AUX_DATA
// @brief holds auxilliary data we need for each ssl
//
typedef struct AUX_DATA {
    //
    // @brief transport params for our endpoint 
    //
    const uint8_t *Tp;

    //
    // @brief peer transport params
    //
    uint8_t *PeerTp;

    //
    // @brief peer transport param len
    //
    size_t PeerTpLen;

    //
    // @brief The current encryption level we are sending data for
    //
    uint32_t Level;

    //
    // @brief this SSL's receive record list
    //
    CXPLAT_LIST_ENTRY RecordList;

    //
    // @brief state tracking for 1_rtt secrets
    SECRET_SET SecretSet[4][2];
} AUX_DATA;

//
// @def GetSslAuxData
// @brief Retrieves application-specific data associated with an SSL object.
//
// This macro accesses the auxiliary data stored in the BIO associated
// with the given SSL connection.
//
// @param s Pointer to an @c SSL object.
//
// @return Pointer to the application-specific data.
//
#define GetSslAuxData(s) BIO_get_app_data(SSL_get_rbio(s))

//
// @brief Determines the negotiated AEAD and hash algorithms from a TLS session.
//
// This function inspects the currently negotiated cipher suite in the given
// TLS context and maps it to corresponding internal AEAD and hash algorithm
// types used by the QUIC implementation.
//
// Supported ciphers include:
// - TLS_AES_128_GCM_SHA256
// - TLS_AES_256_GCM_SHA384
// - TLS_CHACHA20_POLY1305_SHA256
//
// If an unsupported cipher is negotiated, the function asserts.
//
// @param[in]  TlsContext Pointer to the TLS context containing the SSL object.
// @param[out] AeadType   Pointer to receive the negotiated AEAD algorithm type.
// @param[out] HashType   Pointer to receive the negotiated hash algorithm type.
//
void
CxPlatTlsNegotiatedCiphers(
    _In_ CXPLAT_TLS* TlsContext,
    _Out_ CXPLAT_AEAD_TYPE *AeadType,
    _Out_ CXPLAT_HASH_TYPE *HashType
    )
{
    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(TlsContext->Ssl))) {
    case 0x03001301U: // TLS_AES_128_GCM_SHA256
        *AeadType = CXPLAT_AEAD_AES_128_GCM;
        *HashType = CXPLAT_HASH_SHA256;
        break;
    case 0x03001302U: // TLS_AES_256_GCM_SHA384
        *AeadType = CXPLAT_AEAD_AES_256_GCM;
        *HashType = CXPLAT_HASH_SHA384;
        break;
    case 0x03001303U: // TLS_CHACHA20_POLY1305_SHA256
        *AeadType = CXPLAT_AEAD_CHACHA20_POLY1305;
        *HashType = CXPLAT_HASH_SHA256;
        break;
    default:
        CXPLAT_FRE_ASSERT(FALSE);
    }
}

//
// @brief Callback to send TLS handshake data to the QUIC stack.
//
// This function is called by OpenSSL to send handshake data over QUIC.
// It submits the provided buffer to the QUIC connection for transmission.
// If the submission fails, it sets the TLS error on the QUIC connection.
//
// @param[in]  s           Pointer to the SSL connection object.
// @param[in]  buf         Pointer to the buffer containing data to send.
// @param[in]  buf_len     Length of the data in @p buf.
// @param[out] consumed    Number of bytes successfully consumed from @p buf.
// @param[in]  arg         Unused argument (typically NULL).
//
// @return 1 on success, -1 on failure.
//
static int QuicTlsSend(SSL *s, const unsigned char *Buf,
                         size_t BufLen, size_t *Consumed,
                         void *Arg)
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(s);
    CXPLAT_TLS_PROCESS_STATE* TlsState = TlsContext->State;
    struct AUX_DATA *AData = GetSslAuxData(s);

    UNREFERENCED_PARAMETER(Arg);

    //
    // KeyTypes in msquic map directly to our protection levels
    //
    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)AData->Level;

    if (TlsContext->ResultFlags & CXPLAT_TLS_RESULT_ERROR) {
        return -1;
    }

    QuicTraceLogConnVerbose(
        OpenSslAddHandshakeData,
        TlsContext->Connection,
        "Sending %llu handshake bytes (Level = %u)",
        (uint64_t)BufLen,
        (uint32_t)AData->Level);

    //
    // Make sure that we don't violate handshake data lengths
    //
    if (BufLen + TlsState->BufferLength > 0xF000) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Too much handshake data");
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        return -1;
    }

    if (BufLen + TlsState->BufferLength > (size_t)TlsState->BufferAllocLength) {
        //
        // Double the allocated Buffer length until there's enough room for the
        // new data.
        // 
        uint16_t NewBufferAllocLength = TlsState->BufferAllocLength;
        while (BufLen + TlsState->BufferLength > (size_t)NewBufferAllocLength) {
            NewBufferAllocLength <<= 1;
        }

        uint8_t* NewBuffer = CXPLAT_ALLOC_NONPAGED(NewBufferAllocLength, QUIC_POOL_TLS_BUFFER);
        if (NewBuffer == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "New crypto Buffer",
                NewBufferAllocLength);
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            return -1;
        }

        CxPlatCopyMemory(
            NewBuffer,
            TlsState->Buffer,
            TlsState->BufferLength);
        CXPLAT_FREE(TlsState->Buffer, QUIC_POOL_TLS_BUFFER);
        TlsState->Buffer = NewBuffer;
        TlsState->BufferAllocLength = NewBufferAllocLength;
    }

    switch (KeyType) {
    case QUIC_PACKET_KEY_HANDSHAKE:
        if (TlsState->BufferOffsetHandshake == 0) {
            TlsState->BufferOffsetHandshake = TlsState->BufferTotalLength;
            QuicTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                TlsState->BufferOffsetHandshake);
        }
        break;
    case QUIC_PACKET_KEY_1_RTT:
        if (TlsState->BufferOffset1Rtt == 0) {
            TlsState->BufferOffset1Rtt = TlsState->BufferTotalLength;
            QuicTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                TlsState->BufferOffset1Rtt);
        }
        break;
    default:
        break;
    }

    CxPlatCopyMemory(
        TlsState->Buffer + TlsState->BufferLength,
        Buf,
        BufLen);
    TlsState->BufferLength += (uint16_t)BufLen;
    TlsState->BufferTotalLength += (uint16_t)BufLen;

    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_DATA;

    *Consumed = BufLen;
    return 1;
}

//
// @brief Callback to provide a previously buffered TLS record to OpenSSL.
//
// This function is called by OpenSSL to retrieve a TLS record for further
// processing. It searches the buffered records for one matching the given
// SSL connection. If a complete record is found, it is returned via @p buf
// and @p bytes_read. If the record is incomplete, it signals OpenSSL to
// wait for more data.
//
// @param[in]  s            Pointer to the SSL connection object.
// @param[out] buf          Pointer to the buffer containing the record data.
//                          If no data is available, set to NULL.
// @param[out] bytes_read   Length of the record returned in @p buf.
//                          If no data is available, set to 0.
// @param[in]  arg          Unused argument (typically NULL).
//
// @return Always returns 1.
//
static int QuicTlsRcvRec(SSL *s, const unsigned char **Buf, size_t *BytesRead,
                            void *Arg)
{
    RECORD_ENTRY *entry;
    struct AUX_DATA *AData = GetSslAuxData(s);
    CXPLAT_LIST_ENTRY* lentry;

    UNREFERENCED_PARAMETER(Arg);

    CXPLAT_DBG_ASSERT(AData != NULL);

    //
    // Iterate over our received record list looking
    // for a complete entry to submit to the TLS
    // stack
    //
    lentry = AData->RecordList.Flink;
    while (lentry != &AData->RecordList) {
        entry = CXPLAT_CONTAINING_RECORD(lentry, RECORD_ENTRY, Link);
        lentry = lentry->Flink;
        if (entry->Incomplete) {
            return 1;
        }
        if (entry->FreeMe == 1) {
            continue;
        }
        *Buf = entry->Record;
        *BytesRead = entry->RecLen;
        entry->FreeMe = 1;
        break;
  }
  return 1;

}

//
// @brief Callback to release a previously buffered TLS record.
//
// This function is called by OpenSSL after a TLS record has been fully
// processed and can be safely released. It verifies the number of bytes
// read matches the expected record length, frees the associated memory,
// and resets the pointer.
//
// @param[in] bytes_read  The number of bytes processed in the TLS record.
// @param[in] arg         Unused argument (typically NULL).
//
// @return Always returns 1.
//
static int QuicTlsRlsRec(SSL *S, size_t BytesRead,
                            void *Arg)
{
    struct AUX_DATA *AData = GetSslAuxData(S);
    RECORD_ENTRY *entry;
    CXPLAT_LIST_ENTRY* lentry;

    UNREFERENCED_PARAMETER(Arg);

    //
    // Look for Entries that are marked for freeing
    // if the record length matches, we can free it
    //
    lentry = AData->RecordList.Flink;
    while (lentry != &AData->RecordList) {
      entry = CXPLAT_CONTAINING_RECORD(lentry, RECORD_ENTRY, Link);
      lentry = lentry->Flink;
      if ((entry->FreeMe == 1) && (entry->RecLen == BytesRead)) {
        CxPlatListEntryRemove(&entry->Link);
        CXPLAT_FREE(entry, QUIC_POOL_TLS_RECORD_ENTRY);
        return 1;
      }
    }
    return 1;

}

//
// @brief Callback to yield TLS secrets to the QUIC stack.
//
// This function is invoked by OpenSSL to provide traffic secrets during
// the QUIC handshake. It installs the given secret into the msquic QUIC
// connection, either as a read (RX) key or write (TX) key depending on
// the direction.
//
// @param[in] s           Pointer to the SSL connection object.
// @param[in] prot_level  OpenSSL encryption level of the secret.
// @param[in] dir         Direction of the key. 1 for read (RX) key,
//                        0 for write (TX) key.
// @param[in] secret      Pointer to the secret to be installed.
// @param[in] secret_len  Length of the secret.
// @param[in] arg         Unused argument (typically NULL).
//
// @return 1 on success, 0 on failure.
//
#define DIR_READ 0
#define DIR_WRITE 1
static int QuicTlsYieldSecret(SSL *S, uint32_t ProtLevel,
                                 int Dir,
                                 const unsigned char *NewSecret,
                                 size_t SecretLen, void *Arg)
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(S);
    CXPLAT_TLS_PROCESS_STATE* TlsState = TlsContext->State;
    QUIC_PACKET_KEY_TYPE KeyType = (QUIC_PACKET_KEY_TYPE)ProtLevel;
    QUIC_STATUS Status;
    CXPLAT_SECRET Secret;
    struct AUX_DATA *AData = GetSslAuxData(S);

    UNREFERENCED_PARAMETER(Arg);

    QuicTraceLogConnVerbose(
        OpenSslNewEncryptionSecrets,
        TlsContext->Connection,
        "New encryption secrets (Level = %u)",
        ProtLevel);

    if (AData->SecretSet[ProtLevel][Dir].Secret != NULL) {
        return 1;
    }
    
    AData->SecretSet[ProtLevel][Dir].Secret = CXPLAT_ALLOC_NONPAGED(sizeof(struct AUX_DATA), QUIC_POOL_TLS_AUX_DATA);
    if (AData->SecretSet[ProtLevel][Dir].Secret == NULL) {
        return -1;
    }
    memcpy(AData->SecretSet[ProtLevel][Dir].Secret, NewSecret, SecretLen);
    AData->SecretSet[ProtLevel][Dir].SecretLen = SecretLen;

    //
    // Install key immediately unless its a read key and we don't yet
    // have the corresponding write key
    // A notable exception is 0RTT keys on the server, as we only ever get
    // a read key for that.
    //
    if (Dir == 0 && ProtLevel != QUIC_PACKET_KEY_0_RTT &&
        AData->SecretSet[ProtLevel][DIR_WRITE].Secret == NULL) {
        return 1;
    }

    CxPlatTlsNegotiatedCiphers(TlsContext, &Secret.Aead, &Secret.Hash);

    //
    // Tx/Write Secret
    //
    if (AData->SecretSet[ProtLevel][DIR_WRITE].Secret != NULL
        && TlsState->WriteKeys[KeyType] == NULL
        && AData->SecretSet[ProtLevel][DIR_WRITE].installed == 0) {
        CxPlatCopyMemory(Secret.Secret, AData->SecretSet[ProtLevel][DIR_WRITE].Secret, AData->SecretSet[ProtLevel][DIR_WRITE].SecretLen);
        CXPLAT_DBG_ASSERT(TlsState->WriteKeys[KeyType] == NULL);
        Status =
            QuicPacketKeyDerive(
                KeyType,
                TlsContext->HkdfLabels,
                &Secret,
                "write Secret",
                TRUE,
                &TlsState->WriteKeys[KeyType]);
        if (QUIC_FAILED(Status)) {
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            return -1;
        }

        if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_0_RTT) {
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;
            TlsContext->State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
        }
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;
        TlsState->WriteKey = KeyType;
        AData->SecretSet[ProtLevel][DIR_WRITE].installed = 1;
    }
    if (AData->SecretSet[ProtLevel][DIR_READ].Secret != NULL
        && TlsState->ReadKeys[KeyType] == NULL
        && AData->SecretSet[ProtLevel][DIR_READ].installed == 0) {
        CxPlatCopyMemory(Secret.Secret, AData->SecretSet[ProtLevel][DIR_READ].Secret, AData->SecretSet[ProtLevel][DIR_READ].SecretLen);
        Status =
            QuicPacketKeyDerive(
                KeyType,
                TlsContext->HkdfLabels,
                &Secret,
                "read Secret",
                TRUE,
                &TlsState->ReadKeys[KeyType]);
        if (QUIC_FAILED(Status)) {
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            return -1;
        }

        if (TlsContext->IsServer && KeyType == QUIC_PACKET_KEY_1_RTT) {
            // The 1-RTT read keys aren't actually allowed to be used until the 
            // handshake completes.
            // 
        } else { 
            TlsState->ReadKey = KeyType;
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
            AData->SecretSet[ProtLevel][DIR_READ].installed = 1;
        }       
    }
    if (AData->SecretSet[ProtLevel][DIR_READ].installed == 1 && AData->SecretSet[ProtLevel][DIR_WRITE].installed == 1) {
        AData->Level = ProtLevel;
    }

    //
    // If we are installing initial Secrets TlsSecrets aren't allocated yet
    //
    if (TlsContext->TlsSecrets != NULL) {
        //
        // We pass our Secrets one at a time instead of together
        // So we need to map which Secret we're assigning based
        // on whether we are a server, what type of key we're writing
        // and the Direction (1 for write, 0 for read)
        //
        TlsContext->TlsSecrets->SecretLength = (uint8_t)SecretLen;
        switch(KeyType) {
        case QUIC_PACKET_KEY_HANDSHAKE:
            if (TlsContext->IsServer) {
                if (AData->SecretSet[ProtLevel][DIR_WRITE].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ServerHandshakeTrafficSecret,
                           AData->SecretSet[ProtLevel][DIR_WRITE].Secret, AData->SecretSet[ProtLevel][1].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ServerHandshakeTrafficSecret = TRUE;
                }
                if (AData->SecretSet[ProtLevel][DIR_READ].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ClientHandshakeTrafficSecret,
                           AData->SecretSet[ProtLevel][DIR_READ].Secret, AData->SecretSet[ProtLevel][DIR_READ].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ClientHandshakeTrafficSecret = TRUE;
                }
            } else {
                if (AData->SecretSet[ProtLevel][DIR_WRITE].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ClientHandshakeTrafficSecret,
                           AData->SecretSet[ProtLevel][DIR_WRITE].Secret, AData->SecretSet[ProtLevel][DIR_WRITE].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ClientHandshakeTrafficSecret = TRUE;
                } 
                if (AData->SecretSet[ProtLevel][DIR_READ].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ServerHandshakeTrafficSecret,
                           AData->SecretSet[ProtLevel][DIR_READ].Secret, AData->SecretSet[ProtLevel][DIR_READ].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ServerHandshakeTrafficSecret = TRUE;
                }
            }

            break;
        case QUIC_PACKET_KEY_0_RTT:
            if (TlsContext->IsServer) {
                if (AData->SecretSet[ProtLevel][DIR_READ].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ClientEarlyTrafficSecret,
                           AData->SecretSet[ProtLevel][DIR_READ].Secret, AData->SecretSet[ProtLevel][DIR_READ].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ClientEarlyTrafficSecret = TRUE;
                }
            } else {
                if (AData->SecretSet[ProtLevel][DIR_WRITE].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ClientEarlyTrafficSecret,
                           AData->SecretSet[ProtLevel][DIR_WRITE].Secret, AData->SecretSet[ProtLevel][DIR_WRITE].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ClientEarlyTrafficSecret = TRUE;
                }
            }
            break;
        case QUIC_PACKET_KEY_1_RTT:
            if (TlsContext->IsServer) {
                if (AData->SecretSet[ProtLevel][DIR_READ].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ClientTrafficSecret0,
                           AData->SecretSet[ProtLevel][DIR_READ].Secret, AData->SecretSet[ProtLevel][DIR_READ].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
                }
                if (AData->SecretSet[ProtLevel][DIR_WRITE].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ServerTrafficSecret0,
                           AData->SecretSet[ProtLevel][DIR_WRITE].Secret, AData->SecretSet[ProtLevel][DIR_WRITE].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
                }
            } else {
                if (AData->SecretSet[ProtLevel][DIR_READ].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ServerTrafficSecret0,
                           AData->SecretSet[ProtLevel][DIR_READ].Secret, AData->SecretSet[ProtLevel][DIR_READ].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
                }
                if (AData->SecretSet[ProtLevel][DIR_WRITE].Secret != NULL) {
                    memcpy(TlsContext->TlsSecrets->ClientTrafficSecret0,
                           AData->SecretSet[ProtLevel][DIR_WRITE].Secret, AData->SecretSet[ProtLevel][DIR_WRITE].SecretLen);
                    TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
                }
            }
            if (AData->SecretSet[ProtLevel][DIR_READ].Secret != NULL &&
                AData->SecretSet[ProtLevel][DIR_WRITE].Secret != NULL) {
                //
                // We're done installing secrets
                //
                TlsContext->TlsSecrets = NULL;
            }

            break;
        default:
            break;
        }
    }

    return 1;
}

//
// @brief Callback invoked when transport parameters are received from peer.
//
// This function is called by OpenSSL when remote QUIC transport parameters
// are received during the TLS handshake. It decodes and applies these
// parameters to the QUIC connection. If decoding fails, it sets a TLS
// error on the connection.
//
// @param[in] s           Pointer to the SSL connection object.
// @param[in] params      Pointer to the buffer containing transport
//                        parameters from the peer.
// @param[in] params_len  Length of the transport parameters buffer.
// @param[in] arg         Unused argument (typically NULL).
//
// @return 1 on success, -1 on failure.
//
static int QuicTlsGotTp(SSL *S, const unsigned char *Params,
                           size_t ParamsLen, void *Arg)
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(S);
    struct AUX_DATA *AData = GetSslAuxData(S);

    UNREFERENCED_PARAMETER(Arg);

    AData->PeerTp = CXPLAT_ALLOC_NONPAGED(ParamsLen,
                                           QUIC_POOL_TLS_TRANSPARAMS);
    if (AData->PeerTp == NULL) {
        return 0;
    }
    memcpy(AData->PeerTp, Params, ParamsLen);
    AData->PeerTpLen = ParamsLen;
    if (!TlsContext->IsServer && TlsContext->PeerTPReceived == FALSE) {
        if (AData->PeerTp != NULL && AData->PeerTpLen != 0) {
            TlsContext->PeerTPReceived = TRUE;
            if (!TlsContext->SecConfig->Callbacks.ReceiveTP(
                                TlsContext->Connection,
                                (uint16_t)AData->PeerTpLen,
                                AData->PeerTp)) {
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                return 0;
            }
        }
    }
               
    return 1;
}

//
// @brief Callback invoked when a TLS alert is generated or received.
//
// This function is called by OpenSSL when a TLS alert is triggered
// during the handshake or connection. It logs the alert event for
// debugging purposes.
//
// @param[in] s           Pointer to the SSL connection object.
// @param[in] alert_code  The TLS alert code.
// @param[in] arg         Unused argument (typically NULL).
//
// @return Always returns 1.
//
static int QuicTlsAlert(SSL *S,
                          unsigned int AlertCode,
                          void *Arg)
{

    CXPLAT_TLS* TlsContext = SSL_get_app_data(S);
    struct AUX_DATA *AData = GetSslAuxData(S);

    UNREFERENCED_PARAMETER(Arg);

    QuicTraceLogConnError(
        OpenSslAlert,
        TlsContext->Connection,
        "Send alert = %u (Level = %u)",
        AlertCode,
        (uint32_t)AData->Level);
    
    TlsContext->State->AlertCode = (uint16_t)AlertCode;
    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;

    return 1;
}

//
// @brief OpenSSL QUIC TLS callback dispatch table.
//
// This array defines a set of function pointers that OpenSSL uses to
// interact with the QUIC transport layer in a QUIC-enabled TLS session.
// Each entry maps a specific OpenSSL QUIC operation to its corresponding
// callback implementation.
//
// The dispatch table includes:
// - @ref QuicTlsSend: Sends handshake data to the QUIC stack.
// - @ref QuicTlsRcvRec: Provides received handshake data to OpenSSL.
// - @ref QuicTlsRlsRec: Releases processed handshake records.
// - @ref QuicTlsYieldSecret: Supplies derived secrets to the QUIC stack.
// - @ref QuicTlsGotTp: Handles received transport parameters.
// - @ref QuicTlsAlert: Processes TLS alerts.
//
// This table is registered with OpenSSL using SSL_set_quic_tls_cbs().
//
static OSSL_DISPATCH OpenSslQuicDispatch[] = {
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))QuicTlsSend},
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))QuicTlsRcvRec},
    {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))QuicTlsRlsRec},
    {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))QuicTlsYieldSecret},
    {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))QuicTlsGotTp},
    {OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))QuicTlsAlert},
    OSSL_DISPATCH_END
};

extern EVP_CIPHER *CXPLAT_AES_256_CBC_ALG_HANDLE;

uint16_t CxPlatTlsTPHeaderSize = 0;

const size_t OpenSslFilePrefixLength = sizeof("..\\..\\..\\..\\..\\..\\submodules");

#define PFX_PASSWORD_LENGTH 33

//
// Default list of Cipher used.
//
#define CXPLAT_TLS_DEFAULT_SSL_CIPHERS    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

#define CXPLAT_TLS_AES_128_GCM_SHA256       "TLS_AES_128_GCM_SHA256"
#define CXPLAT_TLS_AES_256_GCM_SHA384       "TLS_AES_256_GCM_SHA384"
#define CXPLAT_TLS_CHACHA20_POLY1305_SHA256 "TLS_CHACHA20_POLY1305_SHA256"

//
// Default cert verify depth.
//
#define CXPLAT_TLS_DEFAULT_VERIFY_DEPTH  10

//
// @brief Maps an OpenSSL certificate verification error to a QUIC status code.
//
// This function translates specific OpenSSL X.509 verification error codes
// into corresponding QUIC error status values used by the QUIC transport
// layer. It provides a way to surface TLS-level certificate issues through
// standardized QUIC error codes.
//
// Supported mappings:
// - @c X509_V_ERR_CERT_REJECTED → @c QUIC_STATUS_BAD_CERTIFICATE
// - @c X509_V_ERR_CERT_REVOKED → @c QUIC_STATUS_REVOKED_CERTIFICATE
// - @c X509_V_ERR_CERT_HAS_EXPIRED → @c QUIC_STATUS_CERT_EXPIRED
// - @c X509_V_ERR_CERT_UNTRUSTED,
//   @c X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT → @c QUIC_STATUS_CERT_UNTRUSTED_ROOT
// - All other errors → @c QUIC_STATUS_TLS_ERROR
//
// @param[in] OpenSSLError OpenSSL error code from certificate validation.
//
// @return Corresponding @c QUIC_STATUS value.
//
static
QUIC_STATUS
CxPlatTlsMapOpenSSLErrorToQuicStatus(
    _In_ int OpenSSLError
    )
{
    switch (OpenSSLError) {
    case X509_V_ERR_CERT_REJECTED:
        return QUIC_STATUS_BAD_CERTIFICATE;
    case X509_V_ERR_CERT_REVOKED:
        return QUIC_STATUS_REVOKED_CERTIFICATE;
    case X509_V_ERR_CERT_HAS_EXPIRED:
        return QUIC_STATUS_CERT_EXPIRED;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        __fallthrough;
    case X509_V_ERR_CERT_UNTRUSTED:
        return QUIC_STATUS_CERT_UNTRUSTED_ROOT;
    default:
        return QUIC_STATUS_TLS_ERROR;
    }
}

//
// @brief ALPN selection callback for OpenSSL during TLS handshake.
//
// This callback is invoked by OpenSSL during the TLS handshake to select
// the Application-Layer Protocol Negotiation (ALPN) value to be used.
//
// The selection is driven by QUIC's previously parsed and negotiated ALPN,
// which is already stored in the TLS context. This avoids needing to parse
// the client's offered ALPNs again.
//
// @param[in]  Ssl     Pointer to the SSL object.
// @param[out] Out     On success, set to point to the selected ALPN buffer.
// @param[out] OutLen  On success, set to the length of the selected ALPN.
// @param[in]  In      Pointer to the client's list of ALPN identifiers.
// @param[in]  InLen   Length in bytes of the @p In buffer.
// @param[in]  Arg     Application-provided argument (unused).
//
// @return @c SSL_TLSEXT_ERR_OK to indicate successful selection.
//
static
int
CxPlatTlsAlpnSelectCallback(
    _In_ SSL *Ssl,
    _Out_writes_bytes_(*OutLen) const unsigned char **Out,
    _Out_ unsigned char *OutLen,
    _In_reads_bytes_(InLen) const unsigned char *In,
    _In_ unsigned int InLen,
    _In_ void *Arg
    )
{
    UNREFERENCED_PARAMETER(In);
    UNREFERENCED_PARAMETER(InLen);
    UNREFERENCED_PARAMETER(Arg);

    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    // 
    // QUIC already parsed and picked the ALPN to use and set it in the
    // NegotiatedAlpn variable.
    // 

    CXPLAT_DBG_ASSERT(TlsContext->State->NegotiatedAlpn != NULL);
    *OutLen = TlsContext->State->NegotiatedAlpn[0];
    *Out = TlsContext->State->NegotiatedAlpn + 1;

    return SSL_TLSEXT_ERR_OK;
}

//
// @brief Custom OpenSSL certificate verification callback for OpenSSL.
//
// This function is invoked by OpenSSL during the TLS handshake to verify
// the peer certificate. It handles several QUIC-specific scenarios such as:
// - Disabling or deferring certificate validation.
// - Using QUIC callbacks for certificate verification.
// - Serializing certificates into a portable format when needed.
// - Mapping OpenSSL errors to QUIC status codes.
//
// Behavior depends on the configured credential flags in the associated
// TLS context. It may use OpenSSL’s built-in validation, a custom raw
// certificate verifier, or simply indicate that a certificate was received.
//
// If portable certificates are requested, the peer certificate and chain
// are serialized and passed to the certificate callback. If validation is
// deferred or explicitly disabled, the function ensures certificate
// information is still collected without enforcing verification.
//
// @param[in] x509_ctx
//     Pointer to the OpenSSL certificate verification context.
// @param[in] param
//     Application-defined parameter (unused).
//
// @return Non-zero on success (certificate accepted), zero on failure.
//
static
int
CxPlatTlsCertificateVerifyCallback(
    X509_STORE_CTX *X509Ctx,
    void* Param
    )
{
    UNREFERENCED_PARAMETER(Param);
    int CertificateVerified = 0;
    int status = TRUE;
    unsigned char* OpenSSLCertBuffer = NULL;
    QUIC_BUFFER PortableCertificate = { 0, 0 };
    QUIC_BUFFER PortableChain = { 0, 0 };
    X509* Cert = X509_STORE_CTX_get0_cert(X509Ctx);
    SSL *Ssl = X509_STORE_CTX_get_ex_data(X509Ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    int ValidationResult = X509_V_OK;
    BOOLEAN IsDeferredValidationOrClientAuth =
        (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION ||
        TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION);

    TlsContext->PeerCertReceived = (Cert != NULL);

    if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT ||
        IsDeferredValidationOrClientAuth) &&
        !(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)) {
        if (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION)) {
            if (Cert == NULL) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "No certificate passed");
                X509_STORE_CTX_set_error(X509Ctx, X509_R_NO_CERT_SET_FOR_US_TO_VERIFY);
                return FALSE;
            }

            int OpenSSLCertLength = i2d_X509(Cert, &OpenSSLCertBuffer);
            if (OpenSSLCertLength <= 0) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "i2d_X509 failed");
                CertificateVerified = FALSE;
            } else {
                CertificateVerified =
                    CxPlatCertVerifyRawCertificate(
                        OpenSSLCertBuffer,
                        OpenSSLCertLength,
                        TlsContext->SNI,
                        TlsContext->SecConfig->Flags,
                        IsDeferredValidationOrClientAuth?
                            (uint32_t*)&ValidationResult :
                            NULL);
            }

            if (OpenSSLCertBuffer != NULL) {
                OPENSSL_free(OpenSSLCertBuffer);
            }

            if (!CertificateVerified) {
                X509_STORE_CTX_set_error(X509Ctx, X509_V_ERR_CERT_REJECTED);
            }
        } else {
            CertificateVerified = X509_verify_cert(X509Ctx);

            if (IsDeferredValidationOrClientAuth &&
                CertificateVerified <= 0) {
                ValidationResult =
                    (int)CxPlatTlsMapOpenSSLErrorToQuicStatus(X509_STORE_CTX_get_error(X509Ctx));
            }
        }
    } else if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
               (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES)) {
        //
        // We need to get certificates provided by peer if we going to pass them via Callbacks.CertificateReceived.
        // We don't really care about validation status but without calling X509_verify_cert() X509Ctx has
        // no certificates attached to it and that impacts validation of custom certificate chains.
        //
        // OpenSSL 3 has X509_build_chain() to build just the chain.
        // We may do something similar here for OpenSsl 1.1
        //
        X509_verify_cert(X509Ctx);
    }

    if (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) &&
        !(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) &&
        !CertificateVerified) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Internal certificate validation failed");
        return FALSE;
    }

    if (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) {
        if (Cert) {
            PortableCertificate.Length = i2d_X509(Cert, &PortableCertificate.Buffer);
            if (!PortableCertificate.Buffer) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Failed to serialize certificate context");
                X509_STORE_CTX_set_error(X509Ctx, X509_V_ERR_OUT_OF_MEM);
                return FALSE;
            }
        }
        if (X509Ctx) {
            int ChainCount;
            STACK_OF(X509)* Chain = X509_STORE_CTX_get0_chain(X509Ctx);
            if ((ChainCount = sk_X509_num(Chain)) > 0) {
                PKCS7* p7 = PKCS7_new();
                if (p7) {
                    PKCS7_set_type(p7, NID_pkcs7_signed);
                    PKCS7_content_new(p7, NID_pkcs7_data);

                    for (int i = 0; i < ChainCount; i++) {
                        PKCS7_add_certificate(p7, sk_X509_value(Chain, i));
                    }
                    PortableChain.Length = i2d_PKCS7(p7, &PortableChain.Buffer);
                    PKCS7_free(p7);
                } else {
                    QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "Failed to allocate PKCS7 context");
                }
            }
        }
    }

    if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
        !TlsContext->SecConfig->Callbacks.CertificateReceived(
            TlsContext->Connection,
            (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) ? (QUIC_CERTIFICATE*)&PortableCertificate : (QUIC_CERTIFICATE*)Cert,
            (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) ? (QUIC_CERTIFICATE_CHAIN*)&PortableChain : (QUIC_CERTIFICATE_CHAIN*)X509Ctx,
            0,
            ValidationResult)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Indicate certificate received failed");
        X509_STORE_CTX_set_error(X509Ctx, X509_V_ERR_CERT_REJECTED);
        status = FALSE;
    }

    if (PortableCertificate.Buffer) {
        OPENSSL_free(PortableCertificate.Buffer);
    }
    if (PortableChain.Buffer) {
        OPENSSL_free(PortableChain.Buffer);
    }

    return status;
}

//
// Static build time checks to make sure OpenSSL protection levels
// map correctly to msquic key levels
//
CXPLAT_STATIC_ASSERT((int)0 == (int)QUIC_PACKET_KEY_INITIAL, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)OSSL_RECORD_PROTECTION_LEVEL_EARLY == (int)QUIC_PACKET_KEY_0_RTT, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE == (int)QUIC_PACKET_KEY_HANDSHAKE, "Code assumes exact match!");
CXPLAT_STATIC_ASSERT((int)OSSL_RECORD_PROTECTION_LEVEL_APPLICATION == (int)QUIC_PACKET_KEY_1_RTT, "Code assumes exact match!");

//
// @brief OpenSSL flush flight callback for QUIC.
//
// This callback is invoked by OpenSSL when it's ready to flush a flight
// of handshake data. For QUIC, no action is required here, so the function
// simply returns 1 to indicate success.
//
// @param[in] Ssl Pointer to the SSL object (unused).
//
// @return Always returns 1 to indicate success.
//
int
CxPlatTlsFlushFlightCallback(
    _In_ SSL *Ssl
    )
{
    UNREFERENCED_PARAMETER(Ssl);
    return 1;
}

//
// @brief OpenSSL ClientHello callback used to extract QUIC transport parameters.
//
// This function is called by OpenSSL when parsing the ClientHello message
// during the TLS handshake. It attempts to extract the QUIC transport
// parameters extension using the configured extension type.
//
// If the extension is not present or extraction fails, the TLS context is
// marked with an error, and the appropriate TLS alert is set.
//
// @param[in] Ssl
//     Pointer to the OpenSSL SSL object representing the TLS session.
// @param[out] Alert
//     On failure, receives the TLS alert code to send to the peer.
// @param[in] arg
//     Application-defined argument (unused).
//
// @retval SSL_CLIENT_HELLO_SUCCESS
//     If the transport parameters were successfully found.
// @retval SSL_CLIENT_HELLO_ERROR
//     If an error occurred and the handshake should be aborted.
//
// @note The QUIC transport parameters are expected to be present in
//       the ClientHello as a custom TLS extension.
//
_Success_(return == SSL_CLIENT_HELLO_SUCCESS)
int
CxPlatTlsClientHelloCallback(
    _In_ SSL *Ssl,
    _When_(return == SSL_CLIENT_HELLO_ERROR, _Out_)
        int *Alert,
    _In_ void *arg
    )
{
    UNREFERENCED_PARAMETER(arg);
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    const uint8_t* TransportParams;
    size_t TransportParamLen;

    if (!SSL_client_hello_get0_ext(
            Ssl,
            TlsContext->QuicTpExtType,
            &TransportParams,
            &TransportParamLen)) {
        TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
        *Alert = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    return SSL_CLIENT_HELLO_SUCCESS;
}

//
// @brief Callback invoked when a TLS session ticket is received by the client.
//
// This function is called by OpenSSL when the server issues a session
// ticket to the client. It serializes the session into PEM format and
// passes the data to the QUIC layer using the registered
// @c ReceiveTicket callback.
//
// If serialization fails or the session is too large, appropriate error
// messages are logged. Regardless of success or failure, the function
// returns 0 to indicate OpenSSL should discard the session reference.
//
// @param[in] Ssl
//     Pointer to the SSL object representing the TLS session.
// @param[in] Session
//     Pointer to the received session ticket (as an SSL_SESSION object).
//

int
CxPlatTlsOnClientSessionTicketReceived(
    _In_ SSL *Ssl,
    _In_ SSL_SESSION *Session
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);

    BIO* Bio = BIO_new(BIO_s_mem());
    if (Bio) {
        if (PEM_write_bio_SSL_SESSION(Bio, Session) == 1) {
            uint8_t* Data = NULL;
            long Length = BIO_get_mem_data(Bio, &Data);
            if (Length < UINT16_MAX) {
                QuicTraceLogConnInfo(
                    OpenSslOnRecvTicket,
                    TlsContext->Connection,
                    "Received session ticket, %u bytes",
                    (uint32_t)Length);
                TlsContext->SecConfig->Callbacks.ReceiveTicket(
                    TlsContext->Connection,
                    (uint32_t)Length,
                    Data);
            } else {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Session data too big");
            }
        } else {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "PEM_write_bio_SSL_SESSION failed");
        }
        BIO_free(Bio);
    } else {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            ERR_get_error(),
            "BIO_new_mem_buf failed");
    }

    //
    // We always return a "fail" response so that the session gets freed again
    // because we haven't used the reference.
    // 
    return 0;
}

//
// @brief OpenSSL callback invoked when a session ticket key is needed.
//
// This function is called by OpenSSL during TLS session ticket encryption
// or decryption. It sets up the encryption context (`ctx`) and HMAC context
// (`hctx`) using the configured QUIC ticket key.
//
// On encryption, the function:
// - Generates a random IV.
// - Copies the key ID into @p key_name.
// - Initializes the encryption and HMAC contexts.
//
// On decryption, it:
// - Verifies the key ID matches the current ticket key.
// - Initializes the decryption and HMAC contexts.
//
// OpenSSL 1.1 and 3.0+ are supported via conditional logic using
// `EVP_MAC_CTX` or `HMAC_CTX`, respectively.
//
// @param[in] Ssl
//     Pointer to the OpenSSL SSL object.
// @param[in,out] key_name
//     On encryption, receives the key name (16 bytes).
//     On decryption, contains the key name to match.
// @param[in,out] iv
//     On encryption, receives the randomly generated IV.
//     On decryption, contains the IV used during encryption.
// @param[in,out] ctx
//     Cipher context for encryption or decryption.
// @param[in,out] hctx
//     HMAC or MAC context, depending on OpenSSL version.
// @param[in] enc
//     Non-zero if encrypting a ticket, zero if decrypting.
//
// @return
//     - 1 on success (key matched and contexts initialized).
//     - 0 if key name does not match (decryption only).
//     - -1 on failure (e.g., missing key or random generation failure).
//
// @retval >0
//     Indicates success and that OpenSSL may proceed with ticket handling.
//
// @note This function uses the ticket key stored in the TLS context's
//       security configuration and is required for session resumption
//       via session tickets in QUIC.
//
_Success_(return > 0)
int
CxPlatTlsOnSessionTicketKeyNeeded(
    _In_ SSL *Ssl,
    _When_(enc, _Out_writes_bytes_(16))
    _When_(!enc, _In_reads_bytes_(16))
        unsigned char key_name[16],
    _When_(enc, _Out_writes_bytes_(EVP_MAX_IV_LENGTH))
    _When_(!enc, _In_reads_bytes_(EVP_MAX_IV_LENGTH))
        unsigned char iv[EVP_MAX_IV_LENGTH],
    _Inout_ EVP_CIPHER_CTX *ctx,
    _Inout_ EVP_MAC_CTX *hctx,
    _In_ int enc // Encryption or decryption
    )
{
    OSSL_PARAM params[3];
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    QUIC_TICKET_KEY_CONFIG* TicketKey = TlsContext->SecConfig->TicketKey;

    CXPLAT_DBG_ASSERT(TicketKey != NULL);
    if (TicketKey == NULL) {
        return -1;
    }

    CXPLAT_STATIC_ASSERT(
        sizeof(TicketKey->Id) == 16,
        "key_name and TicketKey->Id are the same size");

    if (enc) {
        if (QUIC_FAILED(CxPlatRandom(EVP_MAX_IV_LENGTH, iv))) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Failed to generate ticket IV");
            return -1; // Insufficient random
        }
        CxPlatCopyMemory(key_name, TicketKey->Id, 16);
        EVP_EncryptInit_ex(ctx, CXPLAT_AES_256_CBC_ALG_HANDLE, NULL, TicketKey->Material, iv);

        params[0] =
            OSSL_PARAM_construct_octet_string(
                OSSL_MAC_PARAM_KEY,
                TicketKey->Material,
                32);
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "sha256", 0);
        params[2] =
            OSSL_PARAM_construct_end();
         EVP_MAC_CTX_set_params(hctx, params);
    } else {
        if (memcmp(key_name, TicketKey->Id, 16) != 0) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Ticket key_name mismatch");
            return 0; // No match
        }
        params[0] =
            OSSL_PARAM_construct_octet_string(
                OSSL_MAC_PARAM_KEY,
                TicketKey->Material,
                32);
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "sha256", 0);
        params[2] =
            OSSL_PARAM_construct_end();
         EVP_MAC_CTX_set_params(hctx, params);
        EVP_DecryptInit_ex(ctx, CXPLAT_AES_256_CBC_ALG_HANDLE, NULL, TicketKey->Material, iv);
    }

    return 1; // This indicates that the ctx and hctx have been set and the
              // session can continue on those parameters.
}

//
// @brief Callback invoked when a session ticket is generated by the server.
//
// This function is called by OpenSSL on the server side after generating
// a TLS session ticket. In this implementation, it performs no action and
// always returns 1 to allow the handshake to continue.
//
// This placeholder exists to support the session ticket generation
// process required for session resumption in TLS/QUIC.
//
// @param[in] Ssl
//     Pointer to the OpenSSL SSL object representing the TLS session.
// @param[in] arg
//     Application-defined argument (unused).
//
// @return Always returns 1 to indicate success.
//
int
CxPlatTlsOnServerSessionTicketGenerated(
    _In_ SSL *Ssl,
    _In_ void *arg
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(arg);
    return 1;
}

//
// @brief Callback invoked when a TLS session ticket is decrypted on the server.
//
// This function is called by OpenSSL when it decrypts a session ticket
// received from a client during the TLS handshake. It determines how
// to proceed based on the ticket decryption status and optionally
// processes application data embedded in the ticket.
//
// If ticket application data is present, it is passed to the QUIC layer
// using the configured @c ReceiveTicket callback. If that callback fails,
// the ticket is ignored.
//
// @param[in] Ssl
//     Pointer to the SSL object representing the TLS session.
// @param[in] Session
//     Pointer to the decrypted SSL session (may contain app data).
// @param[in] keyname
//     Pointer to the name of the key used for decryption (unused).
// @param[in] keyname_length
//     Length of @p keyname in bytes (unused).
// @param[in] status
//     Result of the ticket decryption operation.
//     May be one of:
//     - @c SSL_TICKET_SUCCESS
//     - @c SSL_TICKET_SUCCESS_RENEW
//     - @c SSL_TICKET_NONE
// @param[in] arg
//     Application-defined argument (unused).
//
// @return One of the following to control ticket usage:
//     - @c SSL_TICKET_RETURN_USE: Use the ticket.
//     - @c SSL_TICKET_RETURN_USE_RENEW: Use and renew the ticket.
//     - @c SSL_TICKET_RETURN_IGNORE: Ignore the ticket.
//     - @c SSL_TICKET_RETURN_IGNORE_RENEW: Ignore and renew the ticket.
//
SSL_TICKET_RETURN
CxPlatTlsOnServerSessionTicketDecrypted(
    _In_ SSL *Ssl,
    _In_ SSL_SESSION *Session,
    _In_ const unsigned char *keyname,
    _In_ size_t keyname_length,
    _In_ SSL_TICKET_STATUS status,
    _In_ void *arg
    )
{
    CXPLAT_TLS* TlsContext = SSL_get_app_data(Ssl);
    UNREFERENCED_PARAMETER(keyname);
    UNREFERENCED_PARAMETER(keyname_length);
    UNREFERENCED_PARAMETER(arg);

    QuicTraceLogConnVerbose(
        OpenSslTickedDecrypted,
        TlsContext->Connection,
        "Session ticket decrypted, status %u",
        (uint32_t)status);

    SSL_TICKET_RETURN Result;
    if (status == SSL_TICKET_SUCCESS) {
        Result = SSL_TICKET_RETURN_USE;
    } else if (status == SSL_TICKET_SUCCESS_RENEW) {
        Result = SSL_TICKET_RETURN_USE_RENEW;
    } else {
        Result = SSL_TICKET_RETURN_IGNORE_RENEW;
    }

    uint8_t* Buffer = NULL;
    size_t Length = 0;
    if (Session != NULL &&
        SSL_SESSION_get0_ticket_appdata(Session, (void**)&Buffer, &Length)) {

        QuicTraceLogConnVerbose(
            OpenSslRecvTicketData,
            TlsContext->Connection,
            "Received ticket data, %u bytes",
            (uint32_t)Length);

        if (!TlsContext->SecConfig->Callbacks.ReceiveTicket(
                TlsContext->Connection,
                (uint32_t)Length,
                Buffer)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "ReceiveTicket failed");
            if (status == SSL_TICKET_SUCCESS_RENEW) {
                Result = SSL_TICKET_RETURN_IGNORE_RENEW;
            } else {
                Result = SSL_TICKET_RETURN_IGNORE;
            }
        }
    }

    return Result;
}

CXPLAT_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_FILE, PrivateKeyFile) == FIELD_OFFSET(QUIC_CERTIFICATE_FILE_PROTECTED, PrivateKeyFile),
    "Mismatch (private key) in certificate file structs");

CXPLAT_STATIC_ASSERT(
    FIELD_OFFSET(QUIC_CERTIFICATE_FILE, CertificateFile) == FIELD_OFFSET(QUIC_CERTIFICATE_FILE_PROTECTED, CertificateFile),
    "Mismatch (certificate file) in certificate file structs");

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_TLS_PROVIDER
CxPlatTlsGetProvider(
    void
    )
{
    return QUIC_TLS_PROVIDER_OPENSSL;
}

//
// @brief Creates a QUIC-compatible TLS security configuration.
//
// This function validates and processes a given QUIC credential
// configuration, then constructs a TLS security configuration using
// OpenSSL APIs. The created configuration includes a fully initialized
// `SSL_CTX` with certificate, private key, cipher suites, and TLS options
// according to the specified flags and certificate type.
//
// It supports both synchronous and asynchronous operation modes. On
// successful creation (or immediate failure), the result is returned via
// the `CompletionHandler` callback. On asynchronous operation, the caller
// should wait for the callback invocation before proceeding.
//
// The caller must not use the returned configuration after this call
// unless `CompletionHandler` was invoked with success.
//
// @param[in] CredConfig
//     Pointer to the credential configuration describing certificate type,
//     file paths, revocation options, flags, etc.
//
// @param[in] TlsCredFlags
//     Flags controlling TLS behavior such as session resumption support.
//
// @param[in] TlsCallbacks
//     Pointer to the set of TLS callback functions to bind to this config.
//
// @param[in,opt] Context
//     User-defined context passed to the completion callback.
//
// @param[in] CompletionHandler
//     Callback to invoke once configuration is successfully created or
//     if creation fails.
//
// @return QUIC_STATUS_SUCCESS if the config was created and completion
//         was called synchronously; QUIC_STATUS_PENDING if creation will
//         complete asynchronously; appropriate failure status otherwise.
//
// @note Supported certificate types include:
// - QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE
// - QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED
// - QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12
// - QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH / HASH_STORE / CONTEXT (Windows only)
// - QUIC_CREDENTIAL_TYPE_NONE (client-only)
//
// @remark This function performs deep validation of inputs and flags
//         to ensure compatibility with OpenSSL and QUIC's expectations.
//
// @warning If validation or resource allocation fails at any stage,
//          the configuration will not be created and appropriate errors
//          will be logged via tracing.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    _In_ const CXPLAT_TLS_CALLBACKS* TlsCallbacks,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    QUIC_CREDENTIAL_FLAGS CredConfigFlags = CredConfig->Flags;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS &&
        CredConfig->AsyncHandler == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_ENABLE_OCSP ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE) {
        return QUIC_STATUS_NOT_SUPPORTED; // Not supported by this TLS implementation
    }

#ifdef CX_PLATFORM_USES_TLS_BUILTIN_CERTIFICATE
    CredConfigFlags |= QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION;
#endif

    if ((CredConfigFlags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) &&
        !(CredConfigFlags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED)) {
        return QUIC_STATUS_INVALID_PARAMETER; // Defer validation without indication doesn't make sense.
    }

    if ((CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) &&
        (CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_DISABLE_AIA)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

#ifdef CX_PLATFORM_DARWIN
    if (((CredConfigFlags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) == 0) &&
        (CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY ||
        CredConfigFlags & QUIC_CREDENTIAL_FLAG_DISABLE_AIA)) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
#endif

    if (CredConfig->Reserved != NULL) {
        return QUIC_STATUS_INVALID_PARAMETER; // Not currently used and should be NULL.
    }

    if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
        if (CredConfig->CertificateFile == NULL ||
            CredConfig->CertificateFile->CertificateFile == NULL ||
            CredConfig->CertificateFile->PrivateKeyFile == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
        if (CredConfig->CertificateFileProtected == NULL ||
            CredConfig->CertificateFileProtected->CertificateFile == NULL ||
            CredConfig->CertificateFileProtected->PrivateKeyFile == NULL ||
            CredConfig->CertificateFileProtected->PrivateKeyPassword == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if(CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
        if (CredConfig->CertificatePkcs12 == NULL ||
            CredConfig->CertificatePkcs12->Asn1Blob == NULL ||
            CredConfig->CertificatePkcs12->Asn1BlobLength == 0) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH ||
        CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE ||
        CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) { // NOLINT bugprone-branch-clone
#ifndef _WIN32
        return QUIC_STATUS_NOT_SUPPORTED; // Only supported on windows.
#endif
        // Windows parameters checked later
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_NONE) {
        if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
            return QUIC_STATUS_INVALID_PARAMETER; // Required for server
        }
    } else {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES) {
        if ((CredConfig->AllowedCipherSuites &
            (QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256 |
            QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384 |
            QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256)) == 0) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                CredConfig->AllowedCipherSuites,
                "No valid cipher suites presented");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (CredConfig->AllowedCipherSuites == QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 &&
            !CxPlatCryptSupports(CXPLAT_AEAD_CHACHA20_POLY1305)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                CredConfig->AllowedCipherSuites,
                "Only CHACHA requested but not available");
            return QUIC_STATUS_NOT_SUPPORTED;
        }
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    CXPLAT_SEC_CONFIG* SecurityConfig = NULL;
    X509* X509Cert = NULL;
    EVP_PKEY* PrivateKey = NULL;
    char* CipherSuiteString = NULL;

    //
    // Create a security config.
    //

    SecurityConfig = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_SEC_CONFIG), QUIC_POOL_TLS_SECCONF);
    if (SecurityConfig == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEC_CONFIG",
            sizeof(CXPLAT_SEC_CONFIG));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(SecurityConfig, sizeof(CXPLAT_SEC_CONFIG));
    SecurityConfig->Callbacks = *TlsCallbacks;
    SecurityConfig->Flags = CredConfigFlags;
    SecurityConfig->TlsFlags = TlsCredFlags;

    //
    // Create the a SSL context for the security config.
    //

    SecurityConfig->SSLCtx = SSL_CTX_new(TLS_method());
    if (SecurityConfig->SSLCtx == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    //
    // Configure the SSL context with the defaults.
    //

    Ret = SSL_CTX_set_min_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_min_proto_version failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = SSL_CTX_set_max_proto_version(SecurityConfig->SSLCtx, TLS1_3_VERSION);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_max_proto_version failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    char* CipherSuites = CXPLAT_TLS_DEFAULT_SSL_CIPHERS;
    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES) {
        //
        // Calculate allowed cipher suite string length.
        //
        uint8_t CipherSuiteStringLength = 0;
        uint8_t AllowedCipherSuitesCount = 0;
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256) {
            CipherSuiteStringLength += (uint8_t)sizeof(CXPLAT_TLS_AES_128_GCM_SHA256);
            AllowedCipherSuitesCount++;
        }
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384) {
            CipherSuiteStringLength += (uint8_t)sizeof(CXPLAT_TLS_AES_256_GCM_SHA384);
            AllowedCipherSuitesCount++;
        }
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) {
            if (AllowedCipherSuitesCount == 0 && !CxPlatCryptSupports(CXPLAT_AEAD_CHACHA20_POLY1305)) {
                Status = QUIC_STATUS_NOT_SUPPORTED;
                goto Exit;
            }
            CipherSuiteStringLength += (uint8_t)sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256);
            AllowedCipherSuitesCount++;
        }

        CipherSuiteString = CXPLAT_ALLOC_NONPAGED(CipherSuiteStringLength, QUIC_POOL_TLS_CIPHER_SUITE_STRING);
        if (CipherSuiteString == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CipherSuiteString",
                CipherSuiteStringLength);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }

        //
        // Order of if-statements matters here because OpenSSL uses the order
        // of cipher suites to indicate preference. Below, we use the default
        // order of preference for TLS 1.3 cipher suites.
        //
        uint8_t CipherSuiteStringCursor = 0;
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384) {
            CxPlatCopyMemory(
                &CipherSuiteString[CipherSuiteStringCursor],
                CXPLAT_TLS_AES_256_GCM_SHA384,
                sizeof(CXPLAT_TLS_AES_256_GCM_SHA384));
            CipherSuiteStringCursor += (uint8_t)sizeof(CXPLAT_TLS_AES_256_GCM_SHA384);
            if (--AllowedCipherSuitesCount > 0) {
                CipherSuiteString[CipherSuiteStringCursor - 1] = ':';
            }
        }
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256) {
            CxPlatCopyMemory(
                &CipherSuiteString[CipherSuiteStringCursor],
                CXPLAT_TLS_CHACHA20_POLY1305_SHA256,
                sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256));
            CipherSuiteStringCursor += (uint8_t)sizeof(CXPLAT_TLS_CHACHA20_POLY1305_SHA256);
            if (--AllowedCipherSuitesCount > 0) {
                CipherSuiteString[CipherSuiteStringCursor - 1] = ':';
            }
        }
        if (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256) {
            CxPlatCopyMemory(
                &CipherSuiteString[CipherSuiteStringCursor],
                CXPLAT_TLS_AES_128_GCM_SHA256,
                sizeof(CXPLAT_TLS_AES_128_GCM_SHA256));
            CipherSuiteStringCursor += (uint8_t)sizeof(CXPLAT_TLS_AES_128_GCM_SHA256);
        }
        CXPLAT_DBG_ASSERT(CipherSuiteStringCursor == CipherSuiteStringLength);
        CipherSuites = CipherSuiteString;
    }

    Ret =
        SSL_CTX_set_ciphersuites(
            SecurityConfig->SSLCtx,
            CipherSuites);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            ERR_get_error(),
            "SSL_CTX_set_ciphersuites failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    if (SecurityConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) {
        Ret = SSL_CTX_set_default_verify_paths(SecurityConfig->SSLCtx);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_set_default_verify_paths failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }


    if ((CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT) &&
        !(TlsCredFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {
        SSL_CTX_set_session_cache_mode(
            SecurityConfig->SSLCtx,
            SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(
            SecurityConfig->SSLCtx,
            CxPlatTlsOnClientSessionTicketReceived);
    }

    if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
        if (!(TlsCredFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {
            Ret = SSL_CTX_set_max_early_data(SecurityConfig->SSLCtx, 0xFFFFFFFF);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_set_max_early_data failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }

            Ret = SSL_CTX_set_session_ticket_cb(
                SecurityConfig->SSLCtx,
                NULL,
                CxPlatTlsOnServerSessionTicketDecrypted,
                NULL);
            if (Ret != 1) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "SSL_CTX_set_session_ticket_cb failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        }

        Ret = SSL_CTX_set_num_tickets(SecurityConfig->SSLCtx, 0);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_set_num_tickets failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    //
    // Set the certs.
    //

    if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ||
        CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            SSL_CTX_set_default_passwd_cb_userdata(
                SecurityConfig->SSLCtx, (void*)CredConfig->CertificateFileProtected->PrivateKeyPassword);
        }

        Ret =
            SSL_CTX_use_PrivateKey_file(
                SecurityConfig->SSLCtx,
                CredConfig->CertificateFile->PrivateKeyFile,
                SSL_FILETYPE_PEM);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_use_PrivateKey_file failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret =
            SSL_CTX_use_certificate_chain_file(
                SecurityConfig->SSLCtx,
                CredConfig->CertificateFile->CertificateFile);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_use_certificate_chain_file failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    } else if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
        BIO* Bio = BIO_new(BIO_s_mem());
        PKCS12 *Pkcs12 = NULL;
        const char* Password = NULL;
        char PasswordBuffer[PFX_PASSWORD_LENGTH];

        if (!Bio) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "BIO_new failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        BIO_set_mem_eof_return(Bio, 0);

        if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
            Password = CredConfig->CertificatePkcs12->PrivateKeyPassword;
            Ret =
                BIO_write(
                    Bio,
                    CredConfig->CertificatePkcs12->Asn1Blob,
                    CredConfig->CertificatePkcs12->Asn1BlobLength);
            if (Ret < 0) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "BIO_write failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        } else {
            uint8_t* PfxBlob = NULL;
            uint32_t PfxSize = 0;
            CxPlatRandom(sizeof(PasswordBuffer), PasswordBuffer);

            //
            // Fixup password to printable characters
            //
            for (uint32_t idx = 0; idx < sizeof(PasswordBuffer); ++idx) {
                PasswordBuffer[idx] = ((uint8_t)PasswordBuffer[idx] % 94) + 32;
            }
            PasswordBuffer[PFX_PASSWORD_LENGTH - 1] = 0;
            Password = PasswordBuffer;

            Status =
                CxPlatCertExtractPrivateKey(
                    CredConfig,
                    PasswordBuffer,
                    &PfxBlob,
                    &PfxSize);
            if (QUIC_FAILED(Status)) {
                goto Exit;
            }

            Ret = BIO_write(Bio, PfxBlob, PfxSize);
            CXPLAT_FREE(PfxBlob, QUIC_POOL_TLS_PFX);
            if (Ret < 0) {
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    ERR_get_error(),
                    "BIO_write failed");
                Status = QUIC_STATUS_TLS_ERROR;
                goto Exit;
            }
        }

        Pkcs12 = d2i_PKCS12_bio(Bio, NULL);
        BIO_free(Bio);
        Bio = NULL;

        if (!Pkcs12) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "d2i_PKCS12_bio failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        STACK_OF(X509) *CaCertificates = NULL;
        Ret =
            PKCS12_parse(Pkcs12, Password, &PrivateKey, &X509Cert, &CaCertificates);
        if (CaCertificates) {
            X509* CaCert;
            while ((CaCert = sk_X509_pop(CaCertificates)) != NULL) {
                //
                // This transfers ownership to SSLCtx and CaCert does not need to be freed.
                //
                SSL_CTX_add_extra_chain_cert(SecurityConfig->SSLCtx, CaCert);
            }
            sk_X509_free(CaCertificates);
        }
        if (Pkcs12) {
            PKCS12_free(Pkcs12);
        }
        if (Password == PasswordBuffer) {
            CxPlatZeroMemory(PasswordBuffer, sizeof(PasswordBuffer));
        }

        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "PKCS12_parse failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret =
            SSL_CTX_use_PrivateKey(
                SecurityConfig->SSLCtx,
                PrivateKey);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_use_PrivateKey_file failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret =
            SSL_CTX_use_certificate(
                SecurityConfig->SSLCtx,
                X509Cert);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_use_certificate failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
        Ret = SSL_CTX_check_private_key(SecurityConfig->SSLCtx);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_check_private_key failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE &&
        CredConfig->CaCertificateFile) {
        Ret =
            SSL_CTX_load_verify_locations(
                SecurityConfig->SSLCtx,
                CredConfig->CaCertificateFile,
                NULL);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                ERR_get_error(),
                "SSL_CTX_load_verify_locations failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        SSL_CTX_set_cert_verify_callback(SecurityConfig->SSLCtx, CxPlatTlsCertificateVerifyCallback, NULL);
        SSL_CTX_set_verify(SecurityConfig->SSLCtx, SSL_VERIFY_PEER, NULL);
        if (!(CredConfigFlags & (QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION | QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION))) {
            SSL_CTX_set_verify_depth(SecurityConfig->SSLCtx, CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);
        }

        //
        // TODO - Support additional certificate validation parameters, such as
        // the location of the trusted root CAs (SSL_CTX_load_verify_locations)?
        //

    } else {
        SSL_CTX_set_options(
            SecurityConfig->SSLCtx,
            (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
            SSL_OP_SINGLE_ECDH_USE |
            SSL_OP_CIPHER_SERVER_PREFERENCE |
            SSL_OP_NO_ANTI_REPLAY);
        SSL_CTX_clear_options(SecurityConfig->SSLCtx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
        SSL_CTX_set_mode(SecurityConfig->SSLCtx, SSL_MODE_RELEASE_BUFFERS);

        if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED ||
            CredConfigFlags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
            SSL_CTX_set_cert_verify_callback(
                SecurityConfig->SSLCtx,
                CxPlatTlsCertificateVerifyCallback,
                NULL);
        }

        if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
            int VerifyMode = SSL_VERIFY_PEER;
            if (!(CredConfigFlags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)) {
                SSL_CTX_set_verify_depth(
                    SecurityConfig->SSLCtx,
                    CXPLAT_TLS_DEFAULT_VERIFY_DEPTH);
            }
            if (!(CredConfigFlags & (QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
                QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION))) {
                VerifyMode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
            SSL_CTX_set_verify(
                SecurityConfig->SSLCtx,
                VerifyMode,
                NULL);
        }

        SSL_CTX_set_alpn_select_cb(SecurityConfig->SSLCtx, CxPlatTlsAlpnSelectCallback, NULL);

        SSL_CTX_set_max_early_data(SecurityConfig->SSLCtx, UINT32_MAX);
        SSL_CTX_set_client_hello_cb(SecurityConfig->SSLCtx, CxPlatTlsClientHelloCallback, NULL);
    }

    //
    // Invoke completion inline.
    //

    CompletionHandler(CredConfig, Context, Status, SecurityConfig);
    SecurityConfig = NULL;

    if (CredConfigFlags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        Status = QUIC_STATUS_PENDING;
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

Exit:

    if (SecurityConfig != NULL) {
        CxPlatTlsSecConfigDelete(SecurityConfig);
    }

    if (CipherSuiteString != NULL) {
        CxPlatFree(CipherSuiteString, QUIC_POOL_TLS_CIPHER_SUITE_STRING);
    }

    if (X509Cert != NULL) {
        X509_free(X509Cert);
    }

    if (PrivateKey != NULL) {
        EVP_PKEY_free(PrivateKey);
    }

    return Status;
}

//
// @brief Frees a TLS security configuration previously created by QUIC.
//
// This function releases all resources associated with a
// @c CXPLAT_SEC_CONFIG structure, including the OpenSSL @c SSL_CTX and
// any allocated session ticket keys. It should be called once the security
// configuration is no longer needed.
//
// The pointer passed to this function must have been returned by
// @c CxPlatTlsSecConfigCreate or its associated completion callback.
//
// @param[in] SecurityConfig
//     Pointer to the security configuration to delete. Must not be NULL.
//
// @note After this call, the @p SecurityConfig pointer must not be used.
//
// @remark This function is safe to call at PASSIVE_LEVEL only.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsSecConfigDelete(
    __drv_freesMem(ServerConfig) _Frees_ptr_ _In_
        CXPLAT_SEC_CONFIG* SecurityConfig
    )
{
    if (SecurityConfig->SSLCtx != NULL) {
        SSL_CTX_free(SecurityConfig->SSLCtx);
    }

    if (SecurityConfig->TicketKey != NULL) {
        CXPLAT_FREE(SecurityConfig->TicketKey, QUIC_POOL_TLS_TICKET_KEY);
    }

    CXPLAT_FREE(SecurityConfig, QUIC_POOL_TLS_SECCONF);
}

//
// @brief Sets the session ticket encryption key for a server TLS configuration.
//
// This function assigns a session ticket key to a QUIC server-side TLS
// security configuration. It enables support for session resumption by
// configuring OpenSSL to encrypt and decrypt TLS session tickets using
// the provided key material.
//
// Currently, only the first ticket key in the list is used. Support for
// multiple keys (key rotation) may be added in the future.
//
// @param[in] SecurityConfig
//     Pointer to the server TLS security configuration.
//
// @param[in] KeyConfig
//     Pointer to an array of one or more ticket key configurations.
//     Only the first key is used.
//
// @param[in] KeyCount
//     Number of keys in the @p KeyConfig array. Must be at least 1.
//
// @return
//     - @c QUIC_STATUS_SUCCESS on success.
//     - @c QUIC_STATUS_OUT_OF_MEMORY if memory allocation fails.
//     - @c QUIC_STATUS_NOT_SUPPORTED if called on a client config.
//
// @note This function must not be called for client-side configurations.
// @note Sets OpenSSL's internal callback for session ticket encryption.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigSetTicketKeys(
    _In_ CXPLAT_SEC_CONFIG* SecurityConfig,
    _In_reads_(KeyCount) QUIC_TICKET_KEY_CONFIG* KeyConfig,
    _In_ uint8_t KeyCount
    )
{
    CXPLAT_DBG_ASSERT(KeyCount >= 1); // Only support 1, ignore the rest for now
    UNREFERENCED_PARAMETER(KeyCount);

    if (SecurityConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (SecurityConfig->TicketKey == NULL) {
        SecurityConfig->TicketKey =
            CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_TICKET_KEY_CONFIG), QUIC_POOL_TLS_TICKET_KEY);
        if (SecurityConfig->TicketKey == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "QUIC_TICKET_KEY_CONFIG",
                sizeof(QUIC_TICKET_KEY_CONFIG));
            return QUIC_STATUS_OUT_OF_MEMORY;
        }
    }

    CxPlatCopyMemory(
        SecurityConfig->TicketKey,
        KeyConfig,
        sizeof(QUIC_TICKET_KEY_CONFIG));

    SSL_CTX_set_tlsext_ticket_key_evp_cb(
        SecurityConfig->SSLCtx,
        CxPlatTlsOnSessionTicketKeyNeeded);

    return QUIC_STATUS_SUCCESS;
}

//
// @brief OpenSSL BIO callback to free application-specific auxiliary data.
//
// This function is registered as a callback with a BIO and is called when
// the BIO is being freed. If the operation is @c BIO_CB_FREE, it retrieves
// the custom @c AUX_DATA structure previously stored using
// @c BIO_set_app_data, releases its internal allocations, and clears the
// pointer from the BIO.
//
// This is used in the QUIC TLS layer to clean up transport parameters,
// peer transport parameters, and the auxiliary data struct itself.
//
// @param[in] b
//     Pointer to the BIO being freed.
// @param[in] oper
//     Operation code. Only @c BIO_CB_FREE triggers cleanup.
// @param[in] argp
//     Unused parameter.
// @param[in] len
//     Unused parameter.
// @param[in] argi
//     Unused parameter.
// @param[in] arg1
//     Unused parameter.
// @param[in] ret
//     Return value passed through by OpenSSL.
// @param[in] Processed
//     Unused parameter.
//
// @return The value of @p ret, unmodified.
//
static long FreeBioAuxData(BIO *B, int Oper,
                           const char *ArgP,
                           size_t Len,
                           int ArgInt,
                           long ArgLong,
                           int Ret,
                           size_t *Processed)
{
    struct AUX_DATA *AData;
    int i;
    RECORD_ENTRY *entry;
    CXPLAT_LIST_ENTRY* lentry;

    UNREFERENCED_PARAMETER(ArgP);
    UNREFERENCED_PARAMETER(Len);
    UNREFERENCED_PARAMETER(ArgInt);
    UNREFERENCED_PARAMETER(ArgLong);
    UNREFERENCED_PARAMETER(Processed);

    if (Oper == BIO_CB_FREE) {
        AData = BIO_get_app_data(B);
        CXPLAT_FREE(AData->Tp, QUIC_POOL_TLS_TRANSPARAMS);
        CXPLAT_FREE(AData->PeerTp, QUIC_POOL_TLS_TRANSPARAMS);
        for (i = 0; i < 4; i++) {
            CXPLAT_FREE(AData->SecretSet[i][DIR_READ].Secret, QUIC_POOL_TLS_AUX_DATA);
            CXPLAT_FREE(AData->SecretSet[i][DIR_WRITE].Secret, QUIC_POOL_TLS_AUX_DATA);
        }
        lentry = AData->RecordList.Flink;
        //
        // Free any leftover records
        //
        while (lentry != &AData->RecordList) {
            entry = CXPLAT_CONTAINING_RECORD(lentry, RECORD_ENTRY, Link);
            lentry = lentry->Flink;
            CxPlatListEntryRemove(&entry->Link);
            CXPLAT_FREE(entry, QUIC_POOL_TLS_RECORD_ENTRY);
        }

        CXPLAT_FREE(AData, QUIC_POOL_TLS_AUX_DATA);
        BIO_set_app_data(B, NULL);
    }
    return Ret;
}

//
// @brief Initializes a new QUIC TLS context using OpenSSL.
//
// This function sets up a new TLS context for a QUIC connection by allocating
// and configuring internal structures, creating an OpenSSL SSL object, and
// applying QUIC-specific parameters such as ALPN, SNI, transport parameters,
// and session resumption data.
//
// It supports both client and server roles, and validates all required input
// fields provided via the @p Config parameter.
//
// On success, a fully-initialized `CXPLAT_TLS` object is returned through
// @p NewTlsContext. On failure, all allocated resources are cleaned up.
//
// @param[in] Config
//     Pointer to the configuration structure describing how the TLS context
//     should be initialized (e.g., server/client role, ALPN, SNI, transport
//     parameters, session ticket).
//
// @param[in,out] State
//     Pointer to the TLS processing state (currently unused in this function).
//
// @param[out] NewTlsContext
//     On success, receives a pointer to the initialized `CXPLAT_TLS` context.
//
// @return
//     - `QUIC_STATUS_SUCCESS` on success.
//     - `QUIC_STATUS_OUT_OF_MEMORY` if allocation fails.
//     - `QUIC_STATUS_INVALID_PARAMETER` if input parameters are invalid.
//     - `QUIC_STATUS_TLS_ERROR` if OpenSSL operations fail.
//     - `QUIC_STATUS_INTERNAL_ERROR` on unexpected internal failure.
//
// @note The caller is responsible for calling `CxPlatTlsUninitialize` on the
//       returned context when it is no longer needed.
//
// @remark If session resumption is enabled, a previously saved session ticket
//         may be used for early data.
//
// @remark This function is only safe to call at IRQL <= PASSIVE_LEVEL.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsInitialize(
    _In_ const CXPLAT_TLS_CONFIG* Config,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State,
    _Out_ CXPLAT_TLS** NewTlsContext
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_TLS* TlsContext = NULL;
    uint16_t ServerNameLength = 0;
    UNREFERENCED_PARAMETER(State);
    struct AUX_DATA *AData;
    BIO *ossl_bio = NULL;

    CXPLAT_DBG_ASSERT(Config->HkdfLabels);
    if (Config->SecConfig == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    TlsContext = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_TLS), QUIC_POOL_TLS_CTX);
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(TlsContext, sizeof(CXPLAT_TLS));

    TlsContext->Connection = Config->Connection;
    TlsContext->HkdfLabels = Config->HkdfLabels;
    TlsContext->IsServer = Config->IsServer;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->QuicTpExtType = Config->TPType;
    TlsContext->AlpnBufferLength = Config->AlpnBufferLength;
    TlsContext->AlpnBuffer = Config->AlpnBuffer;
    TlsContext->TlsSecrets = Config->TlsSecrets;

    QuicTraceLogConnVerbose(
        OpenSslContextCreated,
        TlsContext->Connection,
        "TLS context Created");

    if (!Config->IsServer) {

        if (Config->ServerName != NULL) {

            ServerNameLength = (uint16_t)strnlen(Config->ServerName, QUIC_MAX_SNI_LENGTH);
            if (ServerNameLength == QUIC_MAX_SNI_LENGTH) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "SNI Too Long");
                Status = QUIC_STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            TlsContext->SNI = CXPLAT_ALLOC_NONPAGED(ServerNameLength + 1, QUIC_POOL_TLS_SNI);
            if (TlsContext->SNI == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "SNI",
                    ServerNameLength + 1);
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Exit;
            }

            memcpy((char*)TlsContext->SNI, Config->ServerName, ServerNameLength + 1);
        }
    }

    //
    // Create a SSL object for the connection.
    //

    TlsContext->Ssl = SSL_new(Config->SecConfig->SSLCtx);
    if (TlsContext->Ssl == NULL) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "SSL_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    //
    // Both the fuzzer and the HandshakeSpecificLossPattern tests have some
    // issues with larger key shares as introduced by ML-KEM support in openssl
    // The former doesn't expect Client/Server hellos to span multiple udp datagrams
    // and hits a buffer space assertion failure, while the latter times out on loss
    // recovery.  So for now mimic the key shares that schannel offers to work around
    // that
    //
    // TODO: Remove this when the above tests are tolerant of addition of ML-KEM keyshares
    //
    SSL_set1_groups_list(TlsContext->Ssl, "secp256r1:x25519");

    if (!SSL_set_quic_tls_cbs(TlsContext->Ssl, OpenSslQuicDispatch, NULL)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s. ",
            TlsContext->Connection,
            "SSL_set_quic_tls_cbs failed");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    //
    // Note This has to happen after the SSL_set_quic_tls_cbs call
    // as it installs null bios for us
    //
    AData = CXPLAT_ALLOC_NONPAGED(sizeof(struct AUX_DATA), QUIC_POOL_TLS_AUX_DATA);
    if (AData == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Adata",
            sizeof(struct AUX_DATA));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }
    memset(AData, 0, sizeof(struct AUX_DATA));
    CxPlatListInitializeHead(&AData->RecordList);
    ossl_bio = BIO_new(BIO_s_null());
    if (ossl_bio == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Unable to allocate BIO");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit; 
    }
    BIO_set_app_data(ossl_bio, AData);
    BIO_set_callback_ex(ossl_bio, FreeBioAuxData);
    SSL_set_bio(TlsContext->Ssl, ossl_bio, ossl_bio);

    SSL_set_app_data(TlsContext->Ssl, TlsContext);

    if (Config->IsServer) {
        SSL_set_accept_state(TlsContext->Ssl);
    } else {
        SSL_set_connect_state(TlsContext->Ssl);
        SSL_set_tlsext_host_name(TlsContext->Ssl, TlsContext->SNI);
        SSL_set_alpn_protos(TlsContext->Ssl, TlsContext->AlpnBuffer, TlsContext->AlpnBufferLength);
    }

    if (!(Config->SecConfig->TlsFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION)) {

        if (Config->ResumptionTicketLength != 0) {
            CXPLAT_DBG_ASSERT(Config->ResumptionTicketBuffer != NULL);

            QuicTraceLogConnInfo(
                OpenSslOnSetTicket,
                TlsContext->Connection,
                "Setting session ticket, %u bytes",
                Config->ResumptionTicketLength);
            BIO* Bio =
                BIO_new_mem_buf(
                    Config->ResumptionTicketBuffer,
                    (int)Config->ResumptionTicketLength);
            if (Bio) {
                SSL_SESSION* Session = PEM_read_bio_SSL_SESSION(Bio, NULL, 0, NULL);
                if (Session) {
                    if (!SSL_set_session(TlsContext->Ssl, Session)) {
                        QuicTraceEvent(
                            TlsErrorStatus,
                            "[ tls][%p] ERROR, %u, %s.",
                            TlsContext->Connection,
                            ERR_get_error(),
                            "SSL_set_session failed");
                    }
                    SSL_SESSION_free(Session);
                } else {
                    QuicTraceEvent(
                        TlsErrorStatus,
                        "[ tls][%p] ERROR, %u, %s.",
                        TlsContext->Connection,
                        ERR_get_error(),
                        "PEM_read_bio_SSL_SESSION failed");
                }
                BIO_free(Bio);
            } else {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    ERR_get_error(),
                    "BIO_new_mem_buf failed");
            }
        }

        if (Config->IsServer || (Config->ResumptionTicketLength != 0)) {
            SSL_set_quic_tls_early_data_enabled(TlsContext->Ssl, 1);
        }
    }

    if (SSL_set_quic_tls_transport_params(
            TlsContext->Ssl,
            Config->LocalTPBuffer,
            Config->LocalTPLength) != 1) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "SSL_set_quic_transport_params failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }
    AData->Tp = Config->LocalTPBuffer;

    if (Config->ResumptionTicketBuffer) {
        CXPLAT_FREE(Config->ResumptionTicketBuffer, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
    }

    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Exit:

    if (TlsContext != NULL) {
        CxPlatTlsUninitialize(TlsContext);
        TlsContext = NULL;
    }

    return Status;
}

//
// @brief Cleans up and frees a QUIC TLS context.
//
// This function deallocates all memory and resources associated with a
// `CXPLAT_TLS` context, including the OpenSSL `SSL` object and any
// allocated Server Name Indication (SNI) data. It is safe to call with
// a NULL pointer.
//
// This function should be called once a TLS context is no longer in use
// to avoid memory leaks.
//
// @param[in] TlsContext
//     Pointer to the TLS context to clean up. May be NULL.
//
// @note After calling this function, the pointer must not be used again.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {
        QuicTraceLogConnVerbose(
            OpenSslContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");

        if (TlsContext->SNI != NULL) {
            CXPLAT_FREE(TlsContext->SNI, QUIC_POOL_TLS_SNI);
            TlsContext->SNI = NULL;
        }

        if (TlsContext->Ssl != NULL) {
            SSL_free(TlsContext->Ssl);
            TlsContext->Ssl = NULL;
        }

        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
}

//
// @brief Updates the HKDF label set used by the TLS context.
//
// This function assigns a new set of HKDF (HMAC-based Key Derivation Function)
// labels to the given TLS context. These labels are used during QUIC's
// cryptographic key derivation process as part of the TLS handshake.
//
// @param[in] TlsContext
//     Pointer to the TLS context to update.
//
// @param[in] Labels
//     Pointer to the new HKDF labels to assign. Must remain valid for the
//     lifetime of the TLS context or until replaced.
//
// @note This function does not validate or duplicate the label data. The
//       caller must ensure the pointer remains valid.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUpdateHkdfLabels(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ const QUIC_HKDF_LABELS* const Labels
    )
{
    TlsContext->HkdfLabels = Labels;
}

//
// @brief Allocates and initializes a new TLS record entry.
//
// This function creates a new `record_entry` structure, allocates memory
// for a private copy of the given TLS record, and stores its length and
// associated SSL context. The returned structure is used to buffer TLS
// records for later transmission or processing in QUIC.
//
// @param[in] record
//     Pointer to the TLS record data to copy.
//
// @param[in] RecLen
//     Length of the TLS record in bytes.
//
// @param[in] ssl
//     Pointer to the associated OpenSSL `SSL` context.
//
// @return
//     A pointer to the newly allocated `record_entry` on success, or NULL
//     if memory allocation fails.
//
// @note The caller is responsible for freeing the returned structure and
//       its `record` buffer when no longer needed.
//
static RECORD_ENTRY *MakeNewRecord(const uint8_t *Record, size_t RecLen, SSL *Ssl)
{
    RECORD_ENTRY *new;

    //
    // Allocate a new structure, make sure its zeroed out
    //
    new = CXPLAT_ALLOC_NONPAGED(sizeof(RECORD_ENTRY) + RecLen, QUIC_POOL_TLS_RECORD_ENTRY);
    if (new == NULL) {
        return NULL;
    }
    //
    // Copy the Record to its private buffer
    // save the length and Ssl pointer for use in QuicTlsSend
    //
    memcpy(new->Record, Record, RecLen);
    new->RecLen = RecLen;
    new->Ssl = Ssl;
    new->FreeMe = 0;
    new->Incomplete = 0;
    return new;
}

//
// @brief Splits and queues a TLS record for processing by QUIC.
//
// This function examines a `record_entry` that may contain one or more
// TLS handshake messages and determines if it must be split due to:
// - The message being incomplete (spans multiple records).
// - A message requiring isolation (e.g., EncryptedExtensions, type 8).
//
// If a split is necessary, the function adjusts the original record and
// creates a trailing "leftover" record for the remainder. Both records are
// appended to the connection’s TLS processing queue.
//
// @param[in,out] entry
//     Pointer to the TLS record entry to inspect and split if needed.
//
// @returns 1 if an incomplete record was left on the list, -1 if an error
// occured, or 0 if a complete record was made.
//
// @note Message lengths are read from the first 3 bytes of a 4-byte field
//       (TLS handshake header). The total length includes a 1-byte type and
//       a 3-byte length field.
//
// @note Records containing EncryptedExtensions (type 8) must be isolated
//       unless they appear first in the datagram.
//
// @warning Assumes the record buffer contains valid TLS handshake formatting.
// @warning The function asserts that the message type is <= 20.
//
static int SplitAddRecord(RECORD_ENTRY *Entry, size_t *Consumed)
{
    RECORD_ENTRY *leftover = NULL;
    const uint8_t *idx;
    uint8_t message_type;
    size_t total_message_size = 0;
    uint32_t message_size;
    struct AUX_DATA *AData;
    uint8_t Incomplete = 0;
    uint8_t force_split = 0;

    AData = GetSslAuxData(Entry->Ssl);
    CXPLAT_DBG_ASSERT(AData != NULL);
    //
    // set our cursor to the start of the message
    //
    idx = Entry->Record;

    while (total_message_size < Entry->RecLen) {
        message_type = *idx;
        memcpy(&message_size, idx, sizeof(message_size));

        //
        //message size is just the lower 3 bytes of the TLS record
        //
        message_size = htonl(message_size) & 0x00ffffff;

        //
        //make sure our message type is valid
        //
        if (message_type > SSL3_MT_FINISHED) {
            //
            // This is not a real handshake record
            //
            CXPLAT_FREE(Entry, QUIC_POOL_TLS_RECORD_ENTRY);
            return -1;
        }


        //
        // Stop processing if this is a handshake finished record
        //
        if (message_type == SSL3_MT_FINISHED) {
            //
            // Trim the buffer so we end on a record boundary
            // Everything after the HandShakeFinished record
            // Is just padding
            //
            Entry->RecLen = total_message_size + message_size + 4;
            goto insert_now;
        }

        //
        // If this message is larger then the total record length
        // then we need to create an Incomplete record as its remainder
        // is in the next datagram
        // also, if this is an epoch key change message (8 is EncryptedExtensions)
        // then we need to split it as rcv_rec expects that
        // Note we only need to force the split if the epoch change
        // isn't the first message in this record
        //
        if (total_message_size + message_size + 4 > Entry->RecLen) {
            Incomplete = 1;
        }

        if ((message_type == 8) && (total_message_size != 0)) {
            force_split = 1;
        }

        if (Incomplete == 1 || force_split == 1) {
            if (total_message_size == 0) {
                //
                // If this is the first record, just mark this one
                // as being incomplete
                //
                Entry->Incomplete = 1;
            } else {
                //
                //create the incomplete trailing record
                //
                 leftover = MakeNewRecord(idx, Entry->RecLen - total_message_size,
                                                                        Entry->Ssl);
                 //
                 //reduce the size of this Entry to drop whats contained
                 //in the leftover
                 //
                 if (leftover != NULL) {
                     Entry->RecLen -= leftover->RecLen;
                     leftover->Incomplete = Incomplete;
                 }
            }
            break;
        }
        total_message_size += message_size + 4;
        idx += message_size + 4;
    }

    //
    //Add the Entry, and potentially the leftover record
    //

insert_now:
    *Consumed -= Entry->RecLen;
    CxPlatListInsertTail(&AData->RecordList, &Entry->Link);
    if (leftover != NULL) {
        //
        // Make sure the leftover record doesn't need to be split
        // Do so by recursively calling this function.  This will
        // Also add the leftover record to the list
        //
        return SplitAddRecord(leftover, Consumed);
    }
    return Incomplete;
}

//
// @brief Merges a new TLS record fragment into a previously incomplete record.
//
// This function searches the current TLS record list for the given SSL
// connection to find an incomplete record. If one is found, it appends
// the new record data to it, marks the record as complete, and returns
// the updated entry.
//
// If no incomplete record exists, or if the most recent entry is complete,
// the function returns NULL, and the new record should be treated as a
// standalone message.
//
// @param[in] new_record
//     Pointer to the new TLS record fragment to merge.
//
// @param[in] new_RecLen
//     Length of the new record fragment in bytes.
//
// @param[in] new_ssl
//     Pointer to the OpenSSL SSL object associated with the record stream.
//
// @return
//     Pointer to the updated `record_entry` if merged, or NULL if no
//     incomplete record was found or merged.
//
// @note This function assumes the input fragment follows a previously
//       detected split TLS message (e.g., split across multiple QUIC packets).
//
// @warning The function asserts that the record memory allocation succeeds.
//
static RECORD_ENTRY *GetIncompleteRecord(const uint8_t *NewRecord,
                                         size_t NewRecLen,
                                         SSL *NewSsl, size_t *Consumed)
{
    RECORD_ENTRY *entry;
    struct AUX_DATA *AData;
    RECORD_ENTRY *MergedEntry;
    CXPLAT_LIST_ENTRY* lentry;

    AData = GetSslAuxData(NewSsl);

    lentry = AData->RecordList.Flink;
    if (lentry != &AData->RecordList) {
        entry = CXPLAT_CONTAINING_RECORD(lentry, RECORD_ENTRY, Link);
        if (entry->Incomplete) {
            //
            // We have an incomplete record for this SSL
            // merge them
            //
            CxPlatListEntryRemove(&entry->Link);
            MergedEntry = CXPLAT_ALLOC_NONPAGED(sizeof(RECORD_ENTRY) + entry->RecLen + NewRecLen, QUIC_POOL_TLS_RECORD_ENTRY);
            //TmpRec = realloc(entry->Record, entry->RecLen + NewRecLen);
            if (MergedEntry == NULL) {
                return NULL;
            }
            memcpy(MergedEntry->Record, entry->Record, entry->RecLen);
            memcpy(&MergedEntry->Record[entry->RecLen], NewRecord, NewRecLen);
            MergedEntry->RecLen = entry->RecLen + NewRecLen;
            *Consumed += entry->RecLen;
            MergedEntry->Incomplete = 0;
            MergedEntry->FreeMe = 0;
            MergedEntry->Ssl = entry->Ssl;
            CXPLAT_FREE(entry, QUIC_POOL_TLS_RECORD_ENTRY);
            return MergedEntry;
        }
        //
        //current record is complete, nothing to coalesce
        //
        return NULL;
    }
  return NULL;
}

//
// @brief Processes a newly received TLS record for a QUIC connection.
//
// This function handles a new TLS record by either merging it with a
// previously incomplete record (if one exists), or by creating a new
// `record_entry`. The resulting complete or partial record(s) are
// passed to `SplitAddRecord` for potential splitting and queuing.
//
// This is part of the QUIC TLS record processing pipeline and ensures
// correct reconstruction of fragmented handshake messages.
//
// @param[in] ssl
//     Pointer to the OpenSSL SSL object associated with the connection.
//
// @param[in] record
//     Pointer to the newly received TLS record buffer.
//
// @param[in] RecLen
//     Length of the TLS record buffer in bytes.
//
// @return
//     Returns 1 if processing succeeded, 0 if allocation or merge failed
//     or 2 if processing succeded but an incomplete record is at the end of
//     the chain
//
// @note If a matching incomplete record exists, this function merges the
//       data before proceeding.
//
// @warning Assumes valid TLS handshake record formatting.
//
static int ProcessNewMessage(SSL *Ssl, const uint8_t *Record, size_t RecLen, size_t *Consumed)
{
    RECORD_ENTRY *this_rec;
    int SplitRet;
    int Ret = 1;

    this_rec = GetIncompleteRecord(Record, RecLen, Ssl, Consumed);
    if (this_rec == NULL) {
        //
        //No imcomplete Records, just create a new one
        //
        this_rec = MakeNewRecord(Record, RecLen, Ssl);
        if (this_rec == NULL) {
            return 0;
        }
    }

    SplitRet = SplitAddRecord(this_rec, Consumed);

    if (SplitRet == 1) {
        Ret = 2;
    } else if (SplitRet == -1) {
        Ret = 0;
    }
    return Ret;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t* Buffer,
    _Inout_ uint32_t* BufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    )
{
    int Ret;
    int MRet;
    struct AUX_DATA *AData = GetSslAuxData(TlsContext->Ssl);
    RECORD_ENTRY *entry;
    CXPLAT_LIST_ENTRY* lentry;
    size_t Consumed = 0;
    CXPLAT_DBG_ASSERT(Buffer != NULL || *BufferLength == 0);

    TlsContext->State = State;
    TlsContext->ResultFlags = 0;

    if (DataType == CXPLAT_TLS_TICKET_DATA) {
        QuicTraceLogConnVerbose(
            OpenSslSendTicketData,
            TlsContext->Connection,
            "Sending ticket data, %u bytes",
            *BufferLength);

        SSL_SESSION* Session = SSL_get_session(TlsContext->Ssl);
        if (Session == NULL) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "SSL_get_session failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
        if (!SSL_SESSION_set1_ticket_appdata(Session, Buffer, *BufferLength)) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "SSL_SESSION_set1_ticket_appdata failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        if (!SSL_new_session_ticket(TlsContext->Ssl)) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                ERR_get_error(),
                "SSL_new_session_ticket failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }
        Ret = SSL_do_handshake(TlsContext->Ssl);
        if (Ret != 1) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                SSL_get_error(TlsContext->Ssl, Ret),
                "SSL_do_handshake failed");
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
            goto Exit;
        }

        goto Exit;
    }

    if (Buffer != NULL) {
        Consumed = *BufferLength;
        MRet = ProcessNewMessage(TlsContext->Ssl, Buffer,
                                 *BufferLength, &Consumed);
        if (MRet == 0) {
            //
            // There was an allocation failure
            // Indicate we consumed nothing
            //
            Consumed = 0;
        }
        *BufferLength = *BufferLength - (uint32_t)Consumed;
    }

    if (!State->HandshakeComplete) {
more_handshake:
        Ret = SSL_do_handshake(TlsContext->Ssl);
        if (Ret <= 0) {
            int Err = SSL_get_error(TlsContext->Ssl, Ret);
            switch (Err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                goto Exit;
            case SSL_ERROR_SSL: {
                char buf[256];
                const char* file;
                int line;
                ERR_error_string_n(ERR_get_error_all(&file, &line, NULL, NULL, NULL), buf, sizeof(buf));
                QuicTraceLogConnError(
                    OpenSslHandshakeErrorStr,
                    TlsContext->Connection,
                    "TLS handshake error: %s, file:%s:%d",
                    buf,
                    (strlen(file) > OpenSslFilePrefixLength ? file + OpenSslFilePrefixLength : file),
                    line);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }

            default:
                QuicTraceLogConnError(
                    OpenSslHandshakeError,
                    TlsContext->Connection,
                    "TLS handshake error: %d",
                    Err);
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                goto Exit;
            }
        } else {
            lentry = AData->RecordList.Flink;
            if (lentry != &AData->RecordList) {
                entry = CXPLAT_CONTAINING_RECORD(lentry, RECORD_ENTRY, Link);
                //
                // If the first entry on the list is
                // not incomplete, try to move the handshake
                // forward, otherwise we're done here
                //
                if (entry->Incomplete != 1) {
                    goto more_handshake;
                }
            }
        }

        if (TlsContext->State->WriteKey == QUIC_PACKET_KEY_1_RTT
            && AData->SecretSet[QUIC_PACKET_KEY_1_RTT][DIR_READ].Secret != NULL) {
            QuicTraceLogConnInfo(
                OpenSslHandshakeComplete,
                TlsContext->Connection,
                "TLS Handshake complete");
            State->HandshakeComplete = TRUE;
            if (SSL_session_reused(TlsContext->Ssl)) {
                QuicTraceLogConnInfo(
                    OpenSslHandshakeResumed,
                    TlsContext->Connection,
                    "TLS Handshake resumed");
                State->SessionResumed = TRUE;
            }
            if (!TlsContext->IsServer) {
                int EarlyDataStatus = SSL_get_early_data_status(TlsContext->Ssl);
                if (EarlyDataStatus == SSL_EARLY_DATA_ACCEPTED) {
                    State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_ACCEPTED;
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_ACCEPT;

                } else if (EarlyDataStatus == SSL_EARLY_DATA_REJECTED) {
                    State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_REJECTED;
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_EARLY_DATA_REJECT;
                }
            }
            TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE;

            if (TlsContext->IsServer) {
                TlsContext->State->ReadKey = QUIC_PACKET_KEY_1_RTT;
                TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
            }


            if (!TlsContext->IsServer) {
                const uint8_t* NegotiatedAlpn;
                uint32_t NegotiatedAlpnLength;
                SSL_get0_alpn_selected(TlsContext->Ssl, &NegotiatedAlpn, &NegotiatedAlpnLength);
                if (NegotiatedAlpnLength == 0) {
                    QuicTraceLogConnError(
                        OpenSslAlpnNegotiationFailure,
                        TlsContext->Connection,
                        "Failed to negotiate ALPN");
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                    goto Exit;
                }
                if (NegotiatedAlpnLength > UINT8_MAX) {
                    QuicTraceLogConnError(
                        OpenSslInvalidAlpnLength,
                        TlsContext->Connection,
                        "Invalid negotiated ALPN length");
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                    goto Exit;
                }
                TlsContext->State->NegotiatedAlpn =
                    CxPlatTlsAlpnFindInList(
                        TlsContext->AlpnBufferLength,
                        TlsContext->AlpnBuffer,
                        (uint8_t)NegotiatedAlpnLength,
                        NegotiatedAlpn);
                if (TlsContext->State->NegotiatedAlpn == NULL) {
                    QuicTraceLogConnError(
                        OpenSslNoMatchingAlpn,
                        TlsContext->Connection,
                        "Failed to find a matching ALPN");
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                    goto Exit;
                }
            } else if ((TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) &&
                !TlsContext->PeerCertReceived) {
                QUIC_STATUS ValidationResult =
                    (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) &&
                    (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION ||
                    TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION)) ?
                        QUIC_STATUS_CERT_NO_CERT :
                        QUIC_STATUS_SUCCESS;

                if (!TlsContext->SecConfig->Callbacks.CertificateReceived(
                        TlsContext->Connection,
                        NULL,
                        NULL,
                        0,
                        ValidationResult)) {
                    QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "Indicate null certificate received failed");
                    TlsContext->ResultFlags |= CXPLAT_TLS_RESULT_ERROR;
                    TlsContext->State->AlertCode = CXPLAT_TLS_ALERT_CODE_REQUIRED_CERTIFICATE;
                    goto Exit;
                }
            }
        }
    } else {
        SSL_read(TlsContext->Ssl, NULL, 0);
    }

Exit:

    if (!(TlsContext->ResultFlags & CXPLAT_TLS_RESULT_ERROR)) {
        if (State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE] != NULL &&
            State->BufferOffsetHandshake == 0) {
            State->BufferOffsetHandshake = State->BufferTotalLength;
            QuicTraceLogConnInfo(
                OpenSslHandshakeDataStart,
                TlsContext->Connection,
                "Writing Handshake data starts at %u",
                State->BufferOffsetHandshake);
        }
        if (State->WriteKeys[QUIC_PACKET_KEY_1_RTT] != NULL &&
            State->BufferOffset1Rtt == 0) {
            State->BufferOffset1Rtt = State->BufferTotalLength;
            QuicTraceLogConnInfo(
                OpenSsl1RttDataStart,
                TlsContext->Connection,
                "Writing 1-RTT data starts at %u",
                State->BufferOffset1Rtt);
        }
    }

    return TlsContext->ResultFlags;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSecConfigParamSet(
    _In_ CXPLAT_SEC_CONFIG* TlsContext,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSecConfigParamGet(
    _In_ CXPLAT_SEC_CONFIG* SecConfig,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    UNREFERENCED_PARAMETER(SecConfig);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamSet(
    _In_ CXPLAT_TLS* SecConfig,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(SecConfig);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

static
QUIC_STATUS
CxPlatMapCipherSuite(
    _Inout_ QUIC_HANDSHAKE_INFO* HandshakeInfo
    )
{
    //
    // Mappings taken from the following .NET definitions.
    // https://github.com/dotnet/runtime/blob/69425a7e6198ff78131ad64f1aa3fc28202bfde8/src/libraries/Native/Unix/System.Security.Cryptography.Native/pal_ssl.c
    // https://github.com/dotnet/runtime/blob/1d9e50cb4735df46d3de0cee5791e97295eaf588/src/libraries/System.Net.Security/src/System/Net/Security/TlsCipherSuiteData.Lookup.cs
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    HandshakeInfo->KeyExchangeAlgorithm = QUIC_KEY_EXCHANGE_ALGORITHM_NONE;
    HandshakeInfo->KeyExchangeStrength = 0;
    HandshakeInfo->HashStrength = 0;

    switch (HandshakeInfo->CipherSuite) {
        case QUIC_CIPHER_SUITE_TLS_AES_128_GCM_SHA256:
            HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_AES_128;
            HandshakeInfo->CipherStrength = 128;
            HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_256;
            break;
        case QUIC_CIPHER_SUITE_TLS_AES_256_GCM_SHA384:
            HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_AES_256;
            HandshakeInfo->CipherStrength = 256;
            HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_384;
            break;
        case QUIC_CIPHER_SUITE_TLS_CHACHA20_POLY1305_SHA256:
            HandshakeInfo->CipherAlgorithm = QUIC_CIPHER_ALGORITHM_CHACHA20;
            HandshakeInfo->CipherStrength = 256; // TODO - Is this correct?
            HandshakeInfo->Hash = QUIC_HASH_ALGORITHM_SHA_256;
            break;
        default:
            Status = QUIC_STATUS_NOT_SUPPORTED;
            break;
    }

    return Status;
}

static
uint32_t
CxPlatMapVersion(
    _In_z_ const char* Version
    )
{
    if (strcmp(Version, "TLSv1.3") == 0) {
        return QUIC_TLS_PROTOCOL_1_3;
    }
    return QUIC_TLS_PROTOCOL_UNKNOWN;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamGet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {

        case QUIC_PARAM_TLS_HANDSHAKE_INFO: {
            if (*BufferLength < CXPLAT_STRUCT_SIZE_THRU_FIELD(QUIC_HANDSHAKE_INFO, CipherSuite)) {
                *BufferLength = sizeof(QUIC_HANDSHAKE_INFO);
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }

            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            QUIC_HANDSHAKE_INFO* HandshakeInfo = (QUIC_HANDSHAKE_INFO*)Buffer;
            HandshakeInfo->TlsProtocolVersion =
                CxPlatMapVersion(
                    SSL_get_version(TlsContext->Ssl));

            const SSL_CIPHER* Cipher = SSL_get_current_cipher(TlsContext->Ssl);
            if (Cipher == NULL) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Unable to get cipher suite");
                Status = QUIC_STATUS_INVALID_STATE;
                break;
            }
            HandshakeInfo->CipherSuite = SSL_CIPHER_get_protocol_id(Cipher);
            Status = CxPlatMapCipherSuite(HandshakeInfo);
            break;
        }

        case QUIC_PARAM_TLS_NEGOTIATED_ALPN: {

            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            const uint8_t* NegotiatedAlpn;
            unsigned int NegotiatedAlpnLen = 0;
            SSL_get0_alpn_selected(TlsContext->Ssl, &NegotiatedAlpn, &NegotiatedAlpnLen);
            if (NegotiatedAlpnLen == 0) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "Unable to get negotiated alpn");
                Status = QUIC_STATUS_INVALID_STATE;
                break;
            }
            if (*BufferLength < NegotiatedAlpnLen) {
                *BufferLength = NegotiatedAlpnLen;
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }
            *BufferLength = NegotiatedAlpnLen;
            CxPlatCopyMemory(Buffer, NegotiatedAlpn, NegotiatedAlpnLen);
            Status = QUIC_STATUS_SUCCESS;
            break;
        }

        default:
            Status = QUIC_STATUS_NOT_SUPPORTED;
            break;
    }

    return Status;
}

_Success_(return==TRUE)
BOOLEAN
QuicTlsPopulateOffloadKeys(
    _Inout_ CXPLAT_TLS* TlsContext,
    _In_ const QUIC_PACKET_KEY* const PacketKey,
    _In_z_ const char* const SecretName,
    _Inout_ CXPLAT_QEO_CONNECTION* Offload
    )
{
    QUIC_STATUS Status =
        QuicPacketKeyDeriveOffload(
            TlsContext->HkdfLabels,
            PacketKey,
            SecretName,
            Offload);
    if (!QUIC_SUCCEEDED(Status)) {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            Status,
            "QuicTlsPopulateOffloadKeys");
        goto Error;
    }

Error:

    return QUIC_SUCCEEDED(Status);
}
