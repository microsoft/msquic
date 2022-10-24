pwsh ./scripts/build.ps1 -DisableLog -DisablePerf -Parallel 12
./artifacts/bin/linux/x64_Debug_openssl/msquictest --gtest_filter="Handshake/WithHandshakeArgs1.Resume/0"