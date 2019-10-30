
#define QUIC_TEST_APIS 1

#include "quic_datapath.h"
#include "TestAbstractionLayer.h"
#include "msquic.h"
#include "quic_trace.h"
#include "quicdef.h"
#include <time.h>

//
// Some variables need to be defined for the test library.
//

QUIC_API_V1* MsQuic = NULL;
HQUIC Registration = NULL;
QUIC_SEC_CONFIG* SecurityConfig = NULL;

//
// Event to indicate completion of sec config creation operation.
//

static QUIC_EVENT QuicApiTestSecConfigComplete = {0};

//
// Tracks if there are any test failures.
//

static BOOLEAN QuicApiTestFailures = FALSE;

//
// Selfsign cert files used by the tests.
//

static QUIC_SEC_CONFIG_PARAMS* QuicApiSelfSignedCert = NULL;

static
void
QuicApiTestSetUp(
    void
    );

static
void
QuicApiTestTeardown(
    void
    );

static
void
QuicApiTestRunner(
    _In_ ULONG GroupIndex
    );

static
void
QuicApiTestParameterValidation(
    void
    );

static
void
QuicApiTestEventValidation(
    void
    );

static
void
QuicApiTestBasic(
    void
    );

static
void
QuicApiTestHandshake(
    void
    );

static
void
QuicApiTestAppData(
    void
    );

static
void
QuicApiTestMisc(
    void
    );

static
void
QuicApiTestHelp(
    _In_ char *argv[]
    );

//
// Test group info.
//

typedef struct _QUIC_API_TEST_GROUP {
    //
    // The test group runner.
    //

    void (*TestGroupFunc)();

    //
    // The test group name.
    //

    const char* TestGroupName;

} QUIC_API_TEST_GROUP, *PQUIC_API_TEST_GROUP;


//
// The different groups of tests.
//

static QUIC_API_TEST_GROUP QuicApiTestGroup[] = {
    { QuicApiTestParameterValidation,          "PARAMETER VALIDATION TESTS" },
    { QuicApiTestEventValidation,              "EVENT VALIDATION TESTS" },
    { QuicApiTestBasic,                        "BASIC TESTS" },
    { QuicApiTestHandshake,                    "HANDSHAKE TESTS" },
    { QuicApiTestAppData,                      "APPDATA TESTS" },
    { QuicApiTestMisc,                         "MISC TESTS" }
};


static
void
QuicApiTestCreateSecConfigComplete(
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    )
/*++

Routine Description:

    Callback for sec config create completion.

Arguments:

    Context - Context passed to the create secconfig function.

    Status - The status of the create operation.

    SecConfig - The created security config.

Return Value:

    None.

--*/
{
    SecurityConfig = SecConfig;
    QuicEventSet(QuicApiTestSecConfigComplete);
}


static
void
QuicApiTestSetUp(
    void
    )
/*++

Routine Description:

    Sets up the test.

Arguments:

    None.

Return Value:

    None.

--*/
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status = MsQuicOpenV1(&MsQuic);
    TEST_EQUAL(QUIC_STATUS_SUCCESS, Status);

    Status = MsQuic->RegistrationOpen("apitestrunner", &Registration);
    TEST_EQUAL(QUIC_STATUS_SUCCESS, Status);

    QuicEventInitialize(&QuicApiTestSecConfigComplete, TRUE, FALSE);

    QuicApiSelfSignedCert = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
    TEST_NOT_EQUAL(QuicApiSelfSignedCert, NULL);

    Status =
        MsQuic->SecConfigCreate(
            Registration,
            (QUIC_SEC_CONFIG_FLAGS)QuicApiSelfSignedCert->Flags,
            QuicApiSelfSignedCert->Certificate,
            QuicApiSelfSignedCert->Principal,
            NULL,
            QuicApiTestCreateSecConfigComplete);
    TEST_EQUAL(QUIC_STATUS_SUCCESS, Status);

    QuicEventWaitWithTimeout(QuicApiTestSecConfigComplete, 1000);
    QuicEventUninitialize(QuicApiTestSecConfigComplete);
    QuicApiTestSecConfigComplete = NULL;

    TEST_NOT_EQUAL(NULL, SecurityConfig);

    QuicTestInitialize();
}


static
void
QuicApiTestTeardown(
    void
    )
/*++

Routine Description:

    Cleans up the test setup.

Arguments:

    None.

Return Value:

    None.

--*/
{
    QuicPlatFreeSelfSignedCert(QuicApiSelfSignedCert);
    QuicApiSelfSignedCert = NULL;

    MsQuic->SecConfigDelete(SecurityConfig);
    SecurityConfig = NULL;

    MsQuic->RegistrationClose(Registration);
    Registration = NULL;

    MsQuicClose(MsQuic);
    MsQuic = NULL;
}


static
void
QuicApiTestParameterValidation(
    void
    )
/*++

Routine Description:

    Executes QUIC parameter validation tests.

Arguments:

    None.

Return Value:

    None.

--*/
{
    printf("Executing QuicTestValidateRegistration().\n");
    QuicTestValidateRegistration();

    printf("Executing QuicTestValidateSession().\n");
    QuicTestValidateSession();

    printf("Executing QuicTestValidateListener().\n");
    QuicTestValidateListener();

    printf("Executing QuicTestValidateStream(Connect:false).\n");
    QuicTestValidateStream(false);

    printf("Executing QuicTestValidateStream(Connect:true).\n");
    QuicTestValidateStream(true);

    //
    // LINUX_TODO: Test SecConfig
    //

}


static
void
QuicApiTestEventValidation(
    void
    )
/*++

Routine Description:

    Executes QUIC event validation tests.

Arguments:

    None.

Return Value:

    None.

--*/
{
    printf("Executing QuicTestValidateConnectionEvents().\n");
    QuicTestValidateConnectionEvents();

    printf("Executing QuicTestValidateStreamEvents().\n");
    QuicTestValidateStreamEvents();
}


static
void
QuicApiTestBasic(
    void
    )

/*++

Routine Description:

    Executes some basic QUIC API tests.

Arguments:

    None.

Return Value:

    None.

--*/
{
    printf("Executing QuicTestCreateListener().\n");
    QuicTestCreateListener();

    printf("Executing QuicTestStartListener().\n");
    QuicTestStartListener();

    printf("Executing QuicTestStartListenerImplicit(Family: 4).\n");
    QuicTestStartListenerImplicit(4);

    printf("Executing QuicTestStartListenerImplicit(Family: 6).\n");
    QuicTestStartListenerImplicit(6);

    printf("Executing QuicTestStartTwoListeners().\n");
    QuicTestStartTwoListeners();

    printf("Executing QuicTestStartTwoListenersSameALPN().\n");
    QuicTestStartTwoListenersSameALPN();

    printf("Executing QuicTestStartListenerExplicit(Family: 4).\n");
    QuicTestStartListenerExplicit(4);

    printf("Executing QuicTestStartListenerExplicit(Family: 6).\n");
    QuicTestStartListenerExplicit(6);

    printf("Executing QuicTestCreateConnection().\n");
    QuicTestCreateConnection();

    printf("Executing QuicTestBindConnectionImplicit(Family: 4).\n");
    QuicTestBindConnectionImplicit(4);

    printf("Executing QuicTestBindConnectionImplicit(Family: 6).\n");
    QuicTestBindConnectionImplicit(6);

    printf("Executing QuicTestBindConnectionExplicit(Family: 4).\n");
    QuicTestBindConnectionExplicit(4);

    printf("Executing QuicTestBindConnectionExplicit(Family: 6).\n");
    QuicTestBindConnectionExplicit(6);
}


static
void
QuicApiTestHandshake(
    void
    )
/*++

Routine Description:

    Executes some QUIC handshake tests.

Arguments:

    None.

Return Value:

    None.

--*/
{
    int Index = 0;

    typedef struct _TEST_CONFIG {
        int Family;
        BOOLEAN ServerStatelessRetry;
        BOOLEAN MultipleALPNs;
    } TEST_CONFIG;

    TEST_CONFIG TestConfig1[] = {
        { 4, FALSE, FALSE },
        { 4, TRUE, FALSE },
        { 4, FALSE, TRUE },
        { 4, TRUE, TRUE },
        { 6, FALSE, FALSE },
        { 6, TRUE, FALSE },
        { 6, FALSE, TRUE },
        { 6, TRUE, TRUE },
    };

    for (Index = 0; Index < ARRAYSIZE(TestConfig1); Index++) {
        printf("Executing connect test (family:%d, ServerStatelessRetry:%d, MultipleALPNs:%d).\n", TestConfig1[Index].Family, TestConfig1[Index].ServerStatelessRetry, TestConfig1[Index].MultipleALPNs);

        QuicTestConnect(
            TestConfig1[Index].Family,
            TestConfig1[Index].ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            false,  // ClientRebind
            false,  // ChangeMaxStreamID
            TestConfig1[Index].MultipleALPNs,
            false   // AsyncSecConfig
            );
    }

    for (Index = 0; Index < ARRAYSIZE(TestConfig1); Index++) {
        printf("Executing AsyncSecConfig test (Family:%d, ServerStatelessRetry:%d, MultipleALPNs:%d).\n", TestConfig1[Index].Family, TestConfig1[Index].ServerStatelessRetry, TestConfig1[Index].MultipleALPNs);

        QuicTestConnect(
            TestConfig1[Index].Family,
            TestConfig1[Index].ServerStatelessRetry,
            false,  // ClientUsesOldVersion
            false,  // ClientRebind
            false,  // ChangeMaxStreamID
            TestConfig1[Index].MultipleALPNs,
            true    // AsyncSecConfig
            );
    }

    TEST_CONFIG TestConfig2[] = {
        { 4, FALSE, FALSE },
        { 4, TRUE, FALSE },
        { 6, FALSE, FALSE },
        { 6, TRUE, FALSE },
    };

    for (Index = 0; Index < ARRAYSIZE(TestConfig2); Index++) {
        printf("Executing old version test (Family:%d, ServerStatelessRetry:%d).\n", TestConfig2[Index].Family, TestConfig2[Index].ServerStatelessRetry);

        QuicTestConnect(
            TestConfig2[Index].Family,
            TestConfig2[Index].ServerStatelessRetry,
            true,  // ClientUsesOldVersion
            false,  // ClientRebind
            false,  // ChangeMaxStreamID
            TestConfig2[Index].MultipleALPNs,  // MultipleALPNs
            false   // AsyncSecConfig
            );
    }

    TEST_CONFIG TestConfig3[] = {
        { 4, FALSE, FALSE },
        { 6, FALSE, FALSE }
    };

    /* Disabled until core feature support for migration is added.
    for (Index = 0; Index < ARRAYSIZE(TestConfig3); Index++) {
        printf("Executing rebind test (Family:%d).\n", TestConfig3[Index].Family);

        QuicTestConnect(
            TestConfig3[Index].Family,
            false,  // ServerStatelessRetry
            false,  // ClientUsesOldVersion
            true,   // ClientRebind
            false,  // ChangeMaxStreamID
            false,  // MultipleALPNs
            false   // AsyncSecConfig
            );
    }*/

    for (Index = 0; Index < ARRAYSIZE(TestConfig3); Index++) {
        printf("Executing ChangeMaxStreamID test (Family:%d).\n", TestConfig3[Index].Family);

        QuicTestConnect(
            TestConfig3[Index].Family,
            false,  // ServerStatelessRetry
            false,  // ClientUsesOldVersion
            false,  // ClientRebind
            true,   // ChangeMaxStreamID
            false,  // MultipleALPNs
            false   // AsyncSecConfig
            );
    }

    for (Index = 0; Index < ARRAYSIZE(TestConfig3); Index++) {
        printf("Executing QuicTestConnectUnreachable(Family:%d).\n", TestConfig3[Index].Family);

        QuicTestConnectUnreachable(TestConfig3[Index].Family);
    }

    for (Index = 0; Index < ARRAYSIZE(TestConfig3); Index++) {
        printf("Executing QuicTestConnectBadAlpn(Family:%d).\n", TestConfig3[Index].Family);

        QuicTestConnectBadAlpn(TestConfig3[Index].Family);
    }

    for (Index = 0; Index < ARRAYSIZE(TestConfig3); Index++) {
        printf("Executing QuicTestConnectBadSni(Family:%d).\n", TestConfig3[Index].Family);

        QuicTestConnectBadSni(TestConfig3[Index].Family);
    }

    for (Index = 0; Index < ARRAYSIZE(TestConfig3); Index++) {
        printf("Executing QuicTestVersionNegotiation(Family:%d).\n", TestConfig3[Index].Family);

        QuicTestVersionNegotiation(TestConfig3[Index].Family);
    }
}


static
void
QuicApiTestAppData(
    void
    )

/*++

Routine Description:

    Executes some data transfer QUIC tests.

Arguments:

    None.

Return Value:

    None.

--*/
{
    int Index = 0;
    time_t ltime;

    typedef struct _TEST_CONFIG {
        int Family;
        int DataLen;
        int CounnectionCount;
        int StreamCount;
        int BurstCount;
        int BurstDelay;
        BOOLEAN UseSendBuffer;
        BOOLEAN UnidirectionalStreams;
        BOOLEAN ServerInitiatedStreams;
    } TEST_CONFIG;

    TEST_CONFIG TestConfig1[] = {
        { 4, 0, 1, 1, 1, 0, FALSE, FALSE, FALSE },
        { 4, 0, 1, 1, 1, 0, FALSE, TRUE, FALSE },
        { 4, 0, 1, 1, 1, 0, FALSE, FALSE, TRUE },
        { 4, 0, 1, 1, 1, 0, TRUE, TRUE, TRUE },
        { 4, 0, 4, 4, 1, 0, FALSE, FALSE, FALSE },
        { 4, 0, 4, 4, 1, 0, FALSE, TRUE, FALSE },
        { 4, 0, 4, 4, 1, 0, FALSE, FALSE, TRUE },
        { 4, 0, 4, 4, 1, 0, TRUE, TRUE, TRUE },
        { 4, 1000, 1, 1, 1, 0, FALSE, FALSE, FALSE },
        { 4, 1000, 1, 1, 1, 0, FALSE, TRUE, FALSE },
        { 4, 1000, 1, 1, 1, 0, FALSE, FALSE, TRUE },
        { 4, 1000, 1, 1, 1, 0, TRUE, TRUE, TRUE },
        { 4, 1000, 4, 4, 1, 0, FALSE, FALSE, FALSE },
        { 4, 1000, 4, 4, 1, 0, FALSE, TRUE, FALSE },
        { 4, 1000, 4, 4, 1, 0, FALSE, FALSE, TRUE },
        { 4, 1000, 4, 4, 1, 0, TRUE, TRUE, TRUE },
        { 4, 10000, 1, 1, 1, 0, FALSE, FALSE, FALSE },
        { 4, 10000, 1, 1, 1, 0, FALSE, TRUE, FALSE },
        { 4, 10000, 1, 1, 1, 0, FALSE, FALSE, TRUE },
        { 4, 10000, 1, 1, 1, 0, TRUE, TRUE, TRUE },
        { 4, 10000, 4, 4, 1, 0, FALSE, FALSE, FALSE },
        { 4, 10000, 4, 4, 1, 0, FALSE, TRUE, FALSE },
        { 4, 10000, 4, 4, 1, 0, FALSE, FALSE, TRUE },
        { 4, 10000, 4, 4, 1, 0, TRUE, TRUE, TRUE },
        { 6, 0, 1, 1, 1, 0, FALSE, FALSE, FALSE },
        { 6, 0, 1, 1, 1, 0, FALSE, TRUE, FALSE },
        { 6, 0, 1, 1, 1, 0, FALSE, FALSE, TRUE },
        { 6, 0, 1, 1, 1, 0, TRUE, TRUE, TRUE },
        { 6, 0, 4, 4, 1, 0, FALSE, FALSE, FALSE },
        { 6, 0, 4, 4, 1, 0, FALSE, TRUE, FALSE },
        { 6, 0, 4, 4, 1, 0, FALSE, FALSE, TRUE },
        { 6, 0, 4, 4, 1, 0, TRUE, TRUE, TRUE },
        { 6, 1000, 1, 1, 1, 0, FALSE, FALSE, FALSE },
        { 6, 1000, 1, 1, 1, 0, FALSE, TRUE, FALSE },
        { 6, 1000, 1, 1, 1, 0, FALSE, FALSE, TRUE },
        { 6, 1000, 1, 1, 1, 0, TRUE, TRUE, TRUE },
        { 6, 1000, 4, 4, 1, 0, FALSE, FALSE, FALSE },
        { 6, 1000, 4, 4, 1, 0, FALSE, TRUE, FALSE },
        { 6, 1000, 4, 4, 1, 0, FALSE, FALSE, TRUE },
        { 6, 1000, 4, 4, 1, 0, TRUE, TRUE, TRUE },
        { 6, 10000, 1, 1, 1, 0, FALSE, FALSE, FALSE },
        { 6, 10000, 1, 1, 1, 0, FALSE, TRUE, FALSE },
        { 6, 10000, 1, 1, 1, 0, FALSE, FALSE, TRUE },
        { 6, 10000, 1, 1, 1, 0, TRUE, TRUE, TRUE },
        { 6, 10000, 4, 4, 1, 0, FALSE, FALSE, FALSE },
        { 6, 10000, 4, 4, 1, 0, FALSE, TRUE, FALSE },
        { 6, 10000, 4, 4, 1, 0, FALSE, FALSE, TRUE },
        { 6, 10000, 4, 4, 1, 0, TRUE, TRUE, TRUE },
    };

    for (Index = 0; Index < ARRAYSIZE(TestConfig1); Index ++) {
        printf("Executing send test (Family:%d, Length:%d, Conns:%d, Streams:%d, UseSendBuf:%d, UnidirStreams:%d, ServerInitiatedStreams:%d).\n", TestConfig1[Index].Family, TestConfig1[Index].DataLen, TestConfig1[Index].CounnectionCount, TestConfig1[Index].StreamCount, TestConfig1[Index].UseSendBuffer, TestConfig1[Index].UnidirectionalStreams, TestConfig1[Index].ServerInitiatedStreams);

        QuicTestConnectAndPing(
            TestConfig1[Index].Family,
            TestConfig1[Index].DataLen,
            TestConfig1[Index].CounnectionCount,
            TestConfig1[Index].StreamCount,
            TestConfig1[Index].BurstCount,      // StreamBurstCount
            TestConfig1[Index].BurstDelay,      // StreamBurstDelayMs
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            false,  // ClientZeroRtt
            false,  // ServerRejectZeroRtt
            TestConfig1[Index].UseSendBuffer,
            TestConfig1[Index].UnidirectionalStreams,
            TestConfig1[Index].ServerInitiatedStreams
            );
    }

    TEST_CONFIG TestConfig2[] = {
        { 4, 1000000, 1, 1, 1, 0, FALSE, FALSE, FALSE },
        { 4, 1000000, 1, 1, 1, 0, TRUE, FALSE, FALSE },
        { 6, 1000000, 1, 1, 1, 0, FALSE, FALSE, FALSE },
        { 6, 1000000, 1, 1, 1, 0, TRUE, FALSE, FALSE },
    };

    for (Index = 0; Index < ARRAYSIZE(TestConfig2); Index++) {

        printf("Executing large send test (Family:%d, UseSendBuf:%d).\n", TestConfig2[Index].Family, TestConfig2[Index].UseSendBuffer);

        QuicTestConnectAndPing(
            TestConfig2[Index].Family,
            TestConfig2[Index].DataLen,
            TestConfig2[Index].CounnectionCount,
            TestConfig2[Index].StreamCount,
            TestConfig2[Index].BurstCount,
            TestConfig2[Index].BurstDelay,
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            false,
            false,  // ServerRejectZeroRtt
            TestConfig2[Index].UseSendBuffer,
            false,  // UnidirectionalStreams
            false   // ServerInitiatedStreams
            );
    }

    TEST_CONFIG TestConfig3[] = {
        { 4, 1000, 1, 1, 2, 100, FALSE, FALSE, FALSE },
        { 4, 1000, 1, 1, 4, 500, FALSE, FALSE, FALSE },
        { 4, 1000, 1, 1, 8, 1000, FALSE, FALSE, FALSE },
        { 4, 10000, 1, 1, 2, 500, FALSE, FALSE, FALSE },
        { 4, 10000, 1, 1, 4, 1000, FALSE, FALSE, FALSE },
        { 4, 10000, 1, 1, 8, 100, FALSE, FALSE, FALSE },
        { 4, 1000, 1, 1, 2, 100, TRUE, FALSE, FALSE },
        { 4, 1000, 1, 1, 4, 500, TRUE, FALSE, FALSE },
        { 4, 1000, 1, 1, 8, 1000, TRUE, FALSE, FALSE },
        { 4, 10000, 1, 1, 2, 500, TRUE, FALSE, FALSE },
        { 4, 10000, 1, 1, 4, 1000, TRUE, FALSE, FALSE },
        { 4, 10000, 1, 1, 8, 100, TRUE, FALSE, FALSE },
        { 6, 1000, 1, 1, 2, 100, FALSE, FALSE, FALSE },
        { 6, 1000, 1, 1, 4, 500, FALSE, FALSE, FALSE },
        { 6, 1000, 1, 1, 8, 1000, FALSE, FALSE, FALSE },
        { 6, 10000, 1, 1, 2, 1000, FALSE, FALSE, FALSE },
        { 6, 10000, 1, 1, 4, 100, FALSE, FALSE, FALSE },
        { 6, 10000, 1, 1, 8, 500, FALSE, FALSE, FALSE },
        { 6, 1000, 1, 1, 2, 100, TRUE, FALSE, FALSE },
        { 6, 1000, 1, 1, 4, 500, TRUE, FALSE, FALSE },
        { 6, 1000, 1, 1, 8, 1000, TRUE, FALSE, FALSE },
        { 6, 10000, 1, 1, 2, 1000, TRUE, FALSE, FALSE },
        { 6, 10000, 1, 1, 4, 100, TRUE, FALSE, FALSE },
        { 6, 10000, 1, 1, 8, 500, TRUE, FALSE, FALSE },
    };

    for (Index = 0; Index < ARRAYSIZE(TestConfig3); Index++) {
        printf("Executing intermittent send test (Family:%d, Len:%d, BurstCount:%d, BurstDelay:%d, UseSendBuf:%d).\n", TestConfig3[Index].Family, TestConfig3[Index].DataLen, TestConfig3[Index].BurstCount, TestConfig3[Index].BurstDelay, TestConfig3[Index].UseSendBuffer);

        QuicTestConnectAndPing(
            TestConfig3[Index].Family,
            TestConfig3[Index].DataLen,
            TestConfig3[Index].CounnectionCount,
            TestConfig3[Index].StreamCount,
            TestConfig3[Index].BurstCount,
            TestConfig3[Index].BurstDelay,
            false,  // ServerStatelessRetry
            false,  // ClientRebind
            false,  // ClientZeroRtt
            false,  // ServerRejectZeroRtt
            TestConfig3[Index].UseSendBuffer,
            TestConfig3[Index].UnidirectionalStreams,
            TestConfig3[Index].ServerInitiatedStreams
            );
    }
}


static
void
QuicApiTestMisc(
    void
    )
/*++

Routine Description:

    Executes some misc QUIC tests.

Arguments:

    None.

Return Value:

    None.

--*/
{
    printf("Executing QuicTestConnectAndIdle(EnableKeepAlive:false).\n");
    QuicTestConnectAndIdle(false);

    printf("Executing QuicTestConnectAndIdle(EnableKeepAlive:true).\n");
    QuicTestConnectAndIdle(true);

    printf("Executing QuicTestServerDisconnect().\n");
    QuicTestServerDisconnect();

    // This test is currently unreliable.
    // printf("Executing QuicTestClientDisconnect(StopListenerFirst:true).\n");
    // QuicTestClientDisconnect(true);

    // Test is currently unreliable.
    //printf("Executing QuicTestClientDisconnect(StopListenerFirst:false).\n");
    //QuicTestClientDisconnect(false);

    typedef struct _TEST_CONFIG {
        int Family;
        int KeyUpdate;
    } TEST_CONFIG;

    TEST_CONFIG TestConfig[] = {
        { 4, 0 },
        { 4, 1 },
        { 4, 2 },
        { 4, 3 },
        { 6, 0 },
        { 6, 1 },
        { 6, 2 },
        { 6, 3 },
    };

    for (int Index = 0; Index < ARRAYSIZE(TestConfig); Index++) {
        printf("Executing key update test (Family:%d, KeyUpdate:%d).\n", TestConfig[Index].Family, TestConfig[Index].KeyUpdate);
        int KeyUpdate = TestConfig[Index].KeyUpdate;
        QuicTestKeyUpdate(
            TestConfig[Index].Family,
            KeyUpdate == 0 ? 5 : 1,
            0,              // KeyUpdateBytes
            KeyUpdate == 0,
            KeyUpdate & 1,  // ClientKeyUpdate
            KeyUpdate & 2   // ServerKeyUpdate
            );
    }

    typedef struct _ABORT_TEST_CONFIG {
        int Family;
        QUIC_ABORTIVE_TRANSFER_FLAGS Flags;
    } ABORT_TEST_CONFIG;

    ABORT_TEST_CONFIG AbortTestConfig[] = {
        { 4, {0, 0, 0, 0, 1} },
        { 4, {0, 0, 0, 1, 1} },
        { 4, {0, 0, 1, 0, 1} },
        { 4, {0, 0, 1, 1, 1} },
        { 4, {0, 1, 0, 0, 1} },
        { 4, {0, 1, 0, 1, 1} },
        { 4, {0, 1, 1, 0, 1} },
        { 4, {0, 1, 1, 1, 1} },
        { 4, {1, 0, 0, 0, 1} },
        { 4, {1, 0, 0, 1, 1} },
        { 4, {1, 0, 1, 0, 1} },
        { 4, {1, 0, 1, 1, 1} },
        { 4, {1, 1, 0, 0, 1} },
        { 4, {1, 1, 0, 1, 1} },
        { 4, {1, 1, 1, 0, 1} },
        { 4, {1, 1, 1, 1, 1} },

        { 6, {0, 0, 0, 0, 1} },
        { 6, {0, 0, 0, 1, 1} },
        { 6, {0, 0, 1, 0, 1} },
        { 6, {0, 0, 1, 1, 1} },
        { 6, {0, 1, 0, 0, 1} },
        { 6, {0, 1, 0, 1, 1} },
        { 6, {0, 1, 1, 0, 1} },
        { 6, {0, 1, 1, 1, 1} },
        { 6, {1, 0, 0, 0, 1} },
        { 6, {1, 0, 0, 1, 1} },
        { 6, {1, 0, 1, 0, 1} },
        { 6, {1, 0, 1, 1, 1} },
        { 6, {1, 1, 0, 0, 1} },
        { 6, {1, 1, 0, 1, 1} },
        { 6, {1, 1, 1, 0, 1} },
        { 6, {1, 1, 1, 1, 1} }
    };

    for (int Index = 0; Index < ARRAYSIZE(AbortTestConfig); Index++) {
        printf("Executing abortive shutdown test (Family:%d, Flags0x%x).\n", AbortTestConfig[Index].Family, AbortTestConfig[Index].Flags.IntValue);
        QuicAbortiveTransfers(AbortTestConfig[Index].Family, AbortTestConfig[Index].Flags);
    }

    typedef struct _TEST_CONFIG2 {
        int Family;
        uint16_t Iterations;
    } TEST_CONFIG2;

    TEST_CONFIG2 TestConfig2[] = {
        { 4, 1 },
        { 4, 2 },
        { 4, 3 },
        { 6, 1 },
        { 6, 2 },
        { 6, 3 },
    };

    for (int Index = 0; Index < ARRAYSIZE(TestConfig2); Index++) {
        printf("Executing CID update test (Family:%d, Iterations:%d).\n", TestConfig2[Index].Family, TestConfig2[Index].Iterations);
        QuicTestCidUpdate(
            TestConfig2[Index].Family,
            TestConfig2[Index].Iterations
            );
    }
}


static
void
QuicApiTestRunner(
    _In_ ULONG GroupIndex
    )
/*++

Routine Description:

    Executes the test cases in a test group.

Arguments:

    GroupIndex - The index of the test group to execute.

Return Value:

    None.

--*/
{
    UINT64 Start = 0;
    UINT64 End = 0;

    printf("***Starting test group: %s.\n", QuicApiTestGroup[GroupIndex].TestGroupName);

    Start = QuicTimeUs64();
    QuicApiTestGroup[GroupIndex].TestGroupFunc();
    End = QuicTimeUs64();

    printf("***Ending test group: %s, Time elapsed: %lu ms.\n\n", QuicApiTestGroup[GroupIndex].TestGroupName, US_TO_MS(End - Start));
}


static
void
QuicApiTestHelp(
    _In_ char *argv[]
    )
/*++

Routine Description:

    Prints the help text.

Arguments:

    argv - The argument passed.

Return Value:

    None.

--*/
{
    printf("Usage: \n");
    printf("To execute all tests: %s %ld \n", argv[0], ARRAYSIZE(QuicApiTestGroup));
    printf("To execute a specific test: %s <testcaseno> \n", argv[0]);
    printf("Test cases: \n");
    for (ULONG Iter = 0; Iter < ARRAYSIZE(QuicApiTestGroup); Iter++) {
        printf("\t%lu: %s\n", Iter, QuicApiTestGroup[Iter].TestGroupName);
    }
}


int
main(
    _In_ int argc,
    _In_reads_(argc) char *argv[]
    )
/*++

Routine Description:

    Program entry point.

Arguments:

    argc - Number of tokens.

    argv - Array of tokens. The caller will populate the first token with the
        program name/path.

Return Value:

    Exit Code.

--*/
{
    ULONG Input = 0;
    ULONG Iter = 0;

    if (argc != 2) {
        QuicApiTestHelp(argv);
        return 0;
    } else {
        Input = atoi(argv[1]);
    }

    QuicApiTestSetUp();

    if (Input < ARRAYSIZE(QuicApiTestGroup)) {
        QuicApiTestRunner(Input);
    } else if (Input == ARRAYSIZE(QuicApiTestGroup)) {
        for (Iter = 0; Iter < ARRAYSIZE(QuicApiTestGroup); Iter++) {
            QuicApiTestRunner(Iter);
        }
    } else {
        printf("Incorrect Input.\n");
        QuicApiTestHelp(argv);
    }

    if (QuicApiTestFailures)
    {
        printf("WARNING: Test failures detected!!! Check the logs for the failing test case(s).\n");
    }

    QuicApiTestTeardown();
}


void
LogTestFailure(
    const char *File,
    const char *Function,
    int Line,
    const char *Format,
    ...
    )
/*++

Routine Description:

    Callback executed by the test library in case of any failures.

Arguments:

    File - The file name where failure occured.

    Function - The function where failure occured.

    Line - The line number where failure occured.

    Format - The format string followed by variable number of arguments.

Return Value:

    None.

--*/
{
    va_list Args;

    printf("[APItest]: %s() %s:%d ", Function, File, Line);
    va_start(Args, Format);
    vprintf(Format, Args);
    va_end(Args);
    printf("\n");

    QuicApiTestFailures = TRUE;
}
