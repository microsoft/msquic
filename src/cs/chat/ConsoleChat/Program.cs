using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Quic;
using QuicChatLib;

namespace ConsoleChat
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // This code lets us pass in an argument of where to search for the library at.
            // Very helpful for testing
            if (args.Length > 0)
            {
                NativeLibrary.SetDllImportResolver(typeof(MsQuic).Assembly, (libraryName, assembly, searchPath) =>
                {
                    if (libraryName != "msquic") return IntPtr.Zero;
                    if (NativeLibrary.TryLoad(args[0], out var ptr))
                    {
                        return ptr;
                    }
                    return IntPtr.Zero;
                });
            }

            await using Server server = new("F59720999270C8DB5DC8A43B958CC5DC33991E95");
            Console.ReadLine();
            ;

            //await using Client client = new();
            //if (await client.Start("localhost", default))
            //{

            //}
            //else
            //{
            //    Console.WriteLine("Client failed to connect");
            //}
            //;
        }
    }
}
