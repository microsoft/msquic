using System.Net.Quic;

#pragma warning disable CA1416

Console.WriteLine($"QuicConnection.IsSupported = {QuicConnection.IsSupported}");
return QuicConnection.IsSupported ? 0 : 1;
