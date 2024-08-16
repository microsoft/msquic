using System.Net.Quic;

Console.WriteLine($"QuicConnection.IsSupported = {QuicConnection.IsSupported}");
return QuicConnection.IsSupported ? 0 : 1;