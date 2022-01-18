using System;
using System.Reflection;
using Microsoft.Performance.SDK;
using Microsoft.Performance.SDK.Runtime;

namespace QuicTrace
{
    internal class SingleFileAssemblyLoader : IAssemblyLoader
    {
        private readonly string CurrentExePath = Environment.ProcessPath!;

        public bool SupportsIsolation => false;

        public bool IsAssembly(string path)
        {
            return path == CurrentExePath;
        }

        public Assembly? LoadAssembly(string assemblyPath, out ErrorInfo error)
        {
            if (assemblyPath != CurrentExePath)
            {
                error = new ErrorInfo(ErrorCodes.AssemblyLoadFailed, $"AssemblyPath must be {CurrentExePath}, was {assemblyPath}");
                return null;
            }

            error = ErrorInfo.None;
            return typeof(QuicEtwSource).Assembly;
        }
    }
}
