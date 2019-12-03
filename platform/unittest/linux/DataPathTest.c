/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_datapath.h"
#include "msquic.h"

#define LOGINFO(fmt, ...) \
    printf("[INFO]: " fmt "\n", ##__VA_ARGS__)

#define LOGERROR(fmt, ...) \
    printf("[ERROR]: " fmt "\n", ##__VA_ARGS__)


//
// Test case info.
//

typedef struct _DAL_TESTCASE {
    //
    // Test case runner.
    //
    BOOLEAN(*TestCaseFunc)();

    //
    // Test case name.
    //

    char* TestCaseName;

} DAL_TESTCASE, *PDAL_TESTCASE;


//
// Receive context.
//

typedef struct _DAL_TEST_RECV_CONTEXT {
    //
    // The server address.
    //

    QUIC_ADDR ServerAddress;

    //
    // Client receive completion event.
    //

    QUIC_EVENT ClientCompletion;

} DAL_TEST_RECV_CONTEXT;


static const size_t DalTestExpectedDataSize = 1 * 1024;
static char* DalTestExpectedData = NULL;
static uint16_t DalTestNextPortH = 0;
static QUIC_ADDR DalTestLocalIPv4 = {0};
static QUIC_ADDR DalTestLocalIPv6 = {0};
static QUIC_ADDR DalTestZeroIP = {0};


static
void
DalTestResolve(
    _Out_ QUIC_ADDR* SockAddr,
    _In_ QUIC_ADDRESS_FAMILY Af,
    _In_ const char *HostName
    );

static
uint16_t
DalTestGetNextPortH(
    void
    );

static
uint16_t
DalTestGetNextPortN(
    void
    );

static
QUIC_ADDR
DalTestGetNewLocalIPv4(
     bool RandomPort
    );

static
QUIC_ADDR
DalTestGetNewLocalIPv6(
    _In_ bool RandomPort
    );

static
QUIC_ADDR
DalTestGetNewLocalAddr(
    _In_ int AddressFamily,
    _In_ bool RandomPort
    );

static
void
DalTestSetUpTestCase(
    void
    );

static
void
DalTestTearDownTestCase(
    void
    );

static
void
DalTestEmptyReceiveCallback(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void* RecvContext,
    _In_ QUIC_RECV_DATAGRAM* RecvPacket
    );

static
void
DalTestEmptyUnreachableCallback(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void* Context,
    _In_ const QUIC_ADDR* RemoteAddress
    );

static
void
DalTestDataRecvCallback(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void *Context,
    _In_ QUIC_RECV_DATAGRAM* RecvPacket
    );

static
BOOLEAN
DalTestInitialize(
    void
    );

static
BOOLEAN
DalTestInitializeInvalid(
    void
    );

static
BOOLEAN
DalTestBind(
    void
    );

static
BOOLEAN
DalTestRebind(
    void
    );

static
BOOLEAN
DalTestDataSend(
    void
    );

static
BOOLEAN
DalTestDataSendMultiple(
    void
    );

static
void 
DalTestExecuteTestCase(
    _In_ uint32_t TestCaseIndex
    );

static
void
DalTestHelp(
    _In_ char *argv[]
    );


static
void
DalTestResolve(
    _Out_ QUIC_ADDR* SockAddr,
    _In_ QUIC_ADDRESS_FAMILY Af,
    _In_ const char *HostName
    )

{
    int Ret = 0;
    ADDRINFO hints = {0};
    ADDRINFO *ai = NULL;

    //
    // Prepopulate hint with input family.
    //

    hints.ai_family = Af;
    hints.ai_flags = AI_CANONNAME;

    Ret = getaddrinfo(HostName, NULL, &hints, &ai);
    QUIC_FRE_ASSERT(Ret == 0);

    memcpy(SockAddr, ai->ai_addr, ai->ai_addrlen);

    freeaddrinfo(ai);
}


static
uint16_t
DalTestGetNextPortH(
    void
    )

{
    return (++DalTestNextPortH);
}


static
uint16_t
DalTestGetNextPortN(
    void
    )

{
    return htons(DalTestGetNextPortH());
}


static
QUIC_ADDR
DalTestGetNewLocalIPv4(
     bool RandomPort
    )

{
    QUIC_ADDR ipv4Copy = DalTestLocalIPv4;

    if (RandomPort) {
        ipv4Copy.Ipv4.sin_port = DalTestGetNextPortN();
    } else {
        ipv4Copy.Ipv4.sin_port = 0;
    }

    return ipv4Copy;
}


static
QUIC_ADDR
DalTestGetNewLocalIPv6(
    _In_ bool RandomPort
    )

{
    QUIC_ADDR ipv6Copy = DalTestLocalIPv6;

    if (RandomPort) {
        ipv6Copy.Ipv6.sin6_port = DalTestGetNextPortN();
    } else {
        ipv6Copy.Ipv6.sin6_port = 0;
    }

    return ipv6Copy;
}


static
QUIC_ADDR
DalTestGetNewLocalAddr(
    _In_ int AddressFamily,
    _In_ bool RandomPort
    )

{
    if (AddressFamily == 4) {
        return DalTestGetNewLocalIPv4(RandomPort);
    } else if (AddressFamily == 6) {
        return DalTestGetNewLocalIPv6(RandomPort);
    } else {
        QUIC_FRE_ASSERT(FALSE);
        return DalTestZeroIP;
    }
}


static
void
DalTestSetUpTestCase(
    void
    )

{
    //
    // Initialize a semi-random base port number.
    //

    DalTestNextPortH = 50000 + (getpid() % 10000) + (rand() % 5000);

    DalTestResolve(&DalTestLocalIPv4, AF_INET, "localhost");
    DalTestResolve(&DalTestLocalIPv6, AF_INET6, "ip6-localhost");

    DalTestExpectedData = (char*)malloc(DalTestExpectedDataSize);
    QUIC_FRE_ASSERT(DalTestExpectedData != NULL);
}


static
void
DalTestTearDownTestCase(
    void
    )

{
    if (DalTestExpectedData != NULL) {
        free(DalTestExpectedData);
        DalTestExpectedData = NULL;
    }
}


static
void
DalTestEmptyReceiveCallback(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void* RecvContext,
    _In_ QUIC_RECV_DATAGRAM* RecvPacket
    )

{
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(RecvContext);
    UNREFERENCED_PARAMETER(RecvPacket);
    return;
}


static
void
DalTestEmptyUnreachableCallback(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void* Context,
    _In_ const QUIC_ADDR* RemoteAddress
    )

{
    UNREFERENCED_PARAMETER(Binding);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(RemoteAddress);
    return;
}


static
BOOLEAN
DalTestInitialize(
    void
    )

{
    QUIC_DATAPATH* datapath = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status =
        QuicDataPathInitialize(
            0,
            DalTestEmptyReceiveCallback,
            DalTestEmptyUnreachableCallback,
            &datapath);

    if (Status != QUIC_STATUS_SUCCESS) {
        LOGINFO("QuicDataPathInitialize failed");
        return FALSE;
    }

    if (datapath == NULL) {
        LOGINFO("datapth is NULL");
        return FALSE;
    }

    QuicDataPathUninitialize(datapath);

    return TRUE;
}


static
BOOLEAN
DalTestInitializeInvalid(
    void
    )

{
    QUIC_DATAPATH* datapath = NULL;
    QUIC_STATUS Status = QuicDataPathInitialize(0, 0, 0, 0);

    if (Status != QUIC_STATUS_INVALID_PARAMETER) {
        return FALSE;
    }

    return TRUE;
}


static
BOOLEAN
DalTestBind(
    void
    )

{
    QUIC_DATAPATH* datapath = NULL;
    QUIC_DATAPATH_BINDING* binding = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status =
        QuicDataPathInitialize(
            0,
            DalTestEmptyReceiveCallback,
            DalTestEmptyUnreachableCallback,
            &datapath);

    if (Status != QUIC_STATUS_SUCCESS) {
        return FALSE;
    }

    if (Status != QUIC_STATUS_SUCCESS) {
        return FALSE;
    }

    if (datapath == NULL) {
        return FALSE;
    }

    Status =
        QuicDataPathBindingCreate(
            datapath,
            NULL,
            NULL,
            NULL,
            &binding);

    if (Status != QUIC_STATUS_SUCCESS) {
        return FALSE;
    }

    if (binding == NULL) {
        return FALSE;
    }

    QUIC_ADDR Address;
    QuicDataPathBindingGetLocalAddress(binding, &Address);

    if (QuicAddrGetPort(&Address) == (uint16_t)0) {
        return FALSE;
    }

    QuicDataPathBindingDelete(binding);

    QuicDataPathUninitialize(datapath);

    return TRUE;
}


static
BOOLEAN
DalTestRebind(
    void
    )

{
    QUIC_DATAPATH* datapath = NULL;
    QUIC_DATAPATH_BINDING* binding1 = NULL;
    QUIC_DATAPATH_BINDING* binding2 = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status =
        QuicDataPathInitialize(
            0,
            DalTestEmptyReceiveCallback,
            DalTestEmptyUnreachableCallback,
            &datapath);

    if (Status != QUIC_STATUS_SUCCESS) {
        return FALSE;
    }

    if (datapath == NULL) {
        return FALSE;
    }

    Status =
        QuicDataPathBindingCreate(
            datapath,
            NULL,
            NULL,
            NULL,
            &binding1);

    if (Status != QUIC_STATUS_SUCCESS) {
        return FALSE;
    }

    if (binding1 == NULL) {
        return FALSE;
    }

    QUIC_ADDR Address1 = {0};
    QuicDataPathBindingGetLocalAddress(binding1, &Address1);

    if (QuicAddrGetPort(&Address1) == (uint16_t)0) {
        return FALSE;
    }

    Status =
        QuicDataPathBindingCreate(
            datapath,
            NULL,
            NULL,
            NULL,
            &binding2);

    if (Status != QUIC_STATUS_SUCCESS) {
        return FALSE;
    }

    if (binding2 == NULL) {
        return FALSE;
    }

    QUIC_ADDR Address2 = {0};
    QuicDataPathBindingGetLocalAddress(binding2, &Address2);

    if (QuicAddrGetPort(&Address2) == (uint16_t)0) {
        return FALSE;
    }

    QuicDataPathBindingDelete(binding1);
    QuicDataPathBindingDelete(binding2);

    QuicDataPathUninitialize(datapath);

    return TRUE;
}


static
void
DalTestDataRecvCallback(
    _In_ QUIC_DATAPATH_BINDING* Binding,
    _In_ void *Context,
    _In_ QUIC_RECV_DATAGRAM* RecvPacket
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    DAL_TEST_RECV_CONTEXT* RecvContext = (DAL_TEST_RECV_CONTEXT*)Context;

    if (RecvContext == NULL) {
        LOGERROR("RecvContext NULL");
        return;
    }

    if (RecvPacket->BufferLength !=  DalTestExpectedDataSize) {
        LOGERROR("RecvPacket->BufferLength !=  DalTestExpectedDataSize");
        return;
    }

    if (memcmp(RecvPacket->Buffer, DalTestExpectedData, DalTestExpectedDataSize) != 0) {
        LOGERROR("RecvPacket->Buffer !=  DalTestExpectedData");
        return;
    }

    if (QuicAddrGetPort(&RecvPacket->Tuple->LocalAddress) ==
            QuicAddrGetPort(&RecvContext->ServerAddress)) {
        LOGINFO("Sending PONG");
        QUIC_DATAPATH_SEND_CONTEXT* ServerSendContext =
            QuicDataPathBindingAllocSendContext(Binding, 0);

        if (ServerSendContext == NULL) {
            LOGERROR("ServerSendContext == NULL");
            return;
        }

        QUIC_BUFFER *ServerSendBuffer =
            QuicDataPathBindingAllocSendDatagram(ServerSendContext, DalTestExpectedDataSize);

        if (ServerSendBuffer == NULL) {
            LOGERROR("ServerSendBuffer == NULL");
            return;
        }

        memcpy(ServerSendBuffer->Buffer, RecvPacket->Buffer, RecvPacket->BufferLength);

        Status =
            QuicDataPathBindingSendFromTo(
                Binding,
                &RecvPacket->Tuple->LocalAddress,
                &RecvPacket->Tuple->RemoteAddress,
                ServerSendContext);

        if (!QUIC_SUCCEEDED(Status)) {
            LOGERROR("QuicDataPathBindingSendFromTo failed");
            return;
        }
    } else {
        LOGINFO("Received PONG");
        QuicEventSet(RecvContext->ClientCompletion);
    }

    QuicDataPathBindingReturnRecvDatagrams(RecvPacket);
}


static
BOOLEAN
DalTestDataSend(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_DATAPATH* datapath = NULL;
    QUIC_DATAPATH_BINDING* server = NULL;
    QUIC_DATAPATH_BINDING* client = NULL;
    QUIC_ADDR serverAddress = DalTestGetNewLocalAddr(4, TRUE);
    DAL_TEST_RECV_CONTEXT RecvContext = {0};

    QuicEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    Status =
        QuicDataPathInitialize(
            0,
            DalTestDataRecvCallback,
            DalTestEmptyUnreachableCallback,
            &datapath);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicDataPathInitialize failed %ld", Status);
        return FALSE;
    }

    if (datapath == NULL) {
        LOGERROR("Datapath is NULL");
        return FALSE;
    }

    Status = QUIC_STATUS_ADDRESS_IN_USE;

    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        QuicAddrSetPort(&serverAddress, DalTestGetNextPortH());

        Status =
            QuicDataPathBindingCreate(
                datapath,
                &serverAddress,
                NULL,
                &RecvContext,
                &server);
    }

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicDataPathBindingCreate failed %ld", Status);
        return FALSE;
    }

    if(server == NULL) {
        LOGERROR("server is NULL");
        return FALSE;
    }

    QuicDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);

    uint16_t ServerPortH = QuicAddrGetPort(&RecvContext.ServerAddress);

    if (ServerPortH == (uint16_t)0) {
        LOGERROR("QuicAddrGetPort failed %d", ServerPortH);
        return FALSE;
    }

    QuicAddrSetPort(&serverAddress, ServerPortH);

    Status =
        QuicDataPathBindingCreate(
            datapath,
            NULL,
            &serverAddress,
            &RecvContext,
            &client);

    if (client == NULL) {
        LOGERROR("QuicDataPathBindingCreate failed %ld", Status);
        return FALSE;
    }

    QUIC_DATAPATH_SEND_CONTEXT* ClientSendContext =
        QuicDataPathBindingAllocSendContext(client, 0);

    if (ClientSendContext == NULL) {
        LOGERROR("ClientSendContext is NULL");
        return FALSE;
    }

    QUIC_BUFFER *ClientSendBuffer =
        QuicDataPathBindingAllocSendDatagram(ClientSendContext, DalTestExpectedDataSize);

    if (ClientSendBuffer == NULL) {
        LOGERROR("ClientSendBuffer is NULL");
        return FALSE;
    }

    memcpy(ClientSendBuffer->Buffer, DalTestExpectedData, DalTestExpectedDataSize);

    LOGINFO("Sending PING");

    Status =
        QuicDataPathBindingSendTo(
            client,
            &serverAddress,
            ClientSendContext);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicDataPathBindingSendTo failed %ld", Status);
        return FALSE;
    }

    BOOLEAN Signaled = QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 5000);

    if (!Signaled) {
        LOGERROR("Signal failed");
        return FALSE;
    }

    QuicDataPathBindingDelete(client);
    QuicDataPathBindingDelete(server);
    QuicDataPathUninitialize(datapath);

    return TRUE;
}


static
BOOLEAN
DalTestDataSendMultiple(
    void
    )

{
    QUIC_DATAPATH* datapath = NULL;
    QUIC_DATAPATH_BINDING* server = NULL;
    QUIC_DATAPATH_BINDING* client = NULL;
    QUIC_ADDR serverAddress = DalTestGetNewLocalAddr(4, TRUE);
    DAL_TEST_RECV_CONTEXT RecvContext = {0};
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QuicEventInitialize(&RecvContext.ClientCompletion, FALSE, FALSE);

    Status =
        QuicDataPathInitialize(
            0,
            DalTestDataRecvCallback,
            DalTestEmptyUnreachableCallback,
            &datapath);

    if (!QUIC_SUCCEEDED(Status)) {
        return FALSE;
    }

    if (datapath == NULL) {
        return FALSE;
    }

    Status = QUIC_STATUS_ADDRESS_IN_USE;

    while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
        QuicAddrSetPort(&serverAddress, DalTestGetNextPortH());
        Status =
            QuicDataPathBindingCreate(
                datapath,
                &serverAddress,
                NULL,
                &RecvContext,
                &server);
    }

    if (!QUIC_SUCCEEDED(Status)) {
        return FALSE;
    }

    if(server == NULL) {
        return FALSE;
    }

    QuicDataPathBindingGetLocalAddress(server, &RecvContext.ServerAddress);

    uint16_t ServerPortH = QuicAddrGetPort(&RecvContext.ServerAddress);

    if (ServerPortH == 0)
    {
        return FALSE;
    }

    QuicAddrSetPort(&serverAddress, ServerPortH);

    Status =
        QuicDataPathBindingCreate(
            datapath,
            NULL,
            &serverAddress,
            &RecvContext,
            &client);

    if (client == NULL) {
        return FALSE;
    }

    QUIC_DATAPATH_SEND_CONTEXT* ClientSendContext =
        QuicDataPathBindingAllocSendContext(client, 0);

    if (ClientSendContext == NULL) {
        return FALSE;
    }

    QUIC_BUFFER *ClientSendBuffer =
        QuicDataPathBindingAllocSendDatagram(ClientSendContext, DalTestExpectedDataSize);

    if (ClientSendBuffer == NULL) {
        return FALSE;
    }

    memcpy(ClientSendBuffer->Buffer, DalTestExpectedData, DalTestExpectedDataSize);

    LOGINFO("Sending PING");

    Status =
        QuicDataPathBindingSendTo(
            client,
            &serverAddress,
            ClientSendContext);

    if (!QUIC_SUCCEEDED(Status)) {
        return FALSE;
    }

    BOOLEAN Signaled = QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 5000);

    if (!Signaled) {
        return FALSE;
    }

    QuicDataPathBindingDelete(client);
    client = NULL;

    Status =
        QuicDataPathBindingCreate(
            datapath,
            NULL,
            &serverAddress,
            &RecvContext,
            &client);

    if (client == NULL) {
        return FALSE;
    }

    ClientSendContext = QuicDataPathBindingAllocSendContext(client, 0);

    if (ClientSendContext == NULL) {
        return FALSE;
    }

    ClientSendBuffer =
        QuicDataPathBindingAllocSendDatagram(ClientSendContext, DalTestExpectedDataSize);

    if (ClientSendBuffer == NULL) {
        return FALSE;
    }

    memcpy(ClientSendBuffer->Buffer, DalTestExpectedData, DalTestExpectedDataSize);

    LOGINFO("Sending PING");

    Status =
        QuicDataPathBindingSendTo(
            client,
            &serverAddress,
            ClientSendContext);

    if (!QUIC_SUCCEEDED(Status)) {
        return FALSE;
    }

    Signaled = QuicEventWaitWithTimeout(RecvContext.ClientCompletion, 2000);

    if (!Signaled) {
        return FALSE;
    }

    QuicDataPathBindingDelete(client);
    QuicDataPathBindingDelete(server);
    QuicDataPathUninitialize(datapath);

    return TRUE;
}


//
// List of all test cases.
//

static DAL_TESTCASE TestCases[] = {
    { DalTestInitialize, "DalTestInitialize" },
    { DalTestInitializeInvalid, "DalTestInitializeInvalid" },
    { DalTestBind, "DalTestBind" },
    { DalTestRebind, "DalTestRebind" },
    { DalTestDataSend, "DalTestDataSend" },
    { DalTestDataSendMultiple, "DalTestDataSendMultiple" },
};


static
void 
DalTestExecuteTestCase(
    _In_ uint32_t TestCaseIndex
    )

{
    LOGINFO("*Start Testcase: %s.*", TestCases[TestCaseIndex].TestCaseName);
    if ((TestCases[TestCaseIndex].TestCaseFunc)()) {
        LOGINFO("*Testcase succeeded.*");
    } else {
        LOGERROR("*Testcase failed.*");
    }
    LOGINFO("*Stop Testcase:%s.*", TestCases[TestCaseIndex].TestCaseName);
}


static
void
DalTestHelp(
    _In_ char *argv[]
    )

{
    printf("Usage: \n");
    printf("To execute all tests: %s %ld \n", argv[0], ARRAYSIZE(TestCases));
    printf("To execute a specific test: %s <testcaseno> \n", argv[0]);
    printf("Test cases: \n");
    for (uint32_t Iter = 0; Iter < ARRAYSIZE(TestCases); Iter++) {
        printf("\t%lu: %s\n", Iter, TestCases[Iter].TestCaseName);
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
    uint32_t Input = 0;

    if (argc != 2) {
        DalTestHelp(argv);
        return 0;
    }

    DalTestSetUpTestCase();

    Input = atoi(argv[1]);
    if (Input < ARRAYSIZE(TestCases)) {
        DalTestExecuteTestCase(Input);
    } else if (Input == ARRAYSIZE(TestCases)) {
        for (uint32_t Iter = 0; Iter < ARRAYSIZE(TestCases); Iter++) {
            DalTestExecuteTestCase(Iter);
        }
    } else {
        LOGERROR("Incorrect Input");
        DalTestHelp(argv);
    }

    DalTestTearDownTestCase();
}

