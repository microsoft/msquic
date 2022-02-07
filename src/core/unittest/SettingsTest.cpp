/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the settings logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "SettingsTest.cpp.clog.h"
#endif

TEST(SettingsTest, AllSizeTest)
{
    QUIC_SETTINGS IncomingSettings;
    uint8_t Buffer[sizeof(IncomingSettings) * 2];

    for (uint32_t i = 0; i < (uint32_t)FIELD_OFFSET(QUIC_SETTINGS, DesiredVersionsList); i++) {
        uint32_t BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_BUFFER_TOO_SMALL,
            QuicSettingsGetParam(
                &IncomingSettings,
                &BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer)));
        ASSERT_EQ((uint32_t)FIELD_OFFSET(QUIC_SETTINGS, DesiredVersionsList), BufferSize);
    }

    for (uint32_t i = (uint32_t)FIELD_OFFSET(QUIC_SETTINGS, DesiredVersionsList); i <= sizeof(IncomingSettings); i++) {
        uint32_t BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsGetParam(
                &IncomingSettings,
                &BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer)));
        ASSERT_EQ(i, BufferSize);
    }

    for (uint32_t i = sizeof(IncomingSettings); i <= sizeof(Buffer); i++) {
        uint32_t BufferSize = i;
        ASSERT_EQ(
            QUIC_STATUS_SUCCESS,
            QuicSettingsGetParam(
                &IncomingSettings,
                &BufferSize,
                reinterpret_cast<QUIC_SETTINGS*>(Buffer)));
        ASSERT_EQ(sizeof(IncomingSettings), BufferSize);
    }
}
