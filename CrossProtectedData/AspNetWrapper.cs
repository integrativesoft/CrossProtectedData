/*
Copyright (c) 2020 Integrative Software LLC
Created: 1/2020
MIT License
Author: Pablo Carbonell
*/

using Microsoft.AspNetCore.DataProtection;
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

[assembly: InternalsVisibleTo("CrossProtectedTesting")]
namespace Integrative.Encryption
{
    class AspNetWrapper : IProtector
    {
        private const string AppName = "CrossProtect";
        private const string BaseName = "CrossProtected_";

        private static readonly byte[] _emptyBytes = new byte[0];

        public byte[] Protect(byte[] userData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            optionalEntropy = optionalEntropy ?? _emptyBytes;
            var protector = GetProtector(scope, optionalEntropy);
            return protector.Protect(userData);
        }

        public byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            optionalEntropy = optionalEntropy ?? _emptyBytes;
            var protector = GetProtector(scope, optionalEntropy);
            return protector.Unprotect(encryptedData);
        }

        private IDataProtector GetProtector(DataProtectionScope scope, byte[] optionalEntropy)
        {
            if (scope == DataProtectionScope.CurrentUser)
            {
                return GetUserProtector(optionalEntropy);
            }
            else
            {
                return GetMachineProtector(optionalEntropy);
            }
        }

        private IDataProtector GetUserProtector(byte[] optionalEntropy)
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var path = Path.Combine(appData, AppName);
            var info = new DirectoryInfo(path);
            var provider = DataProtectionProvider.Create(info);
            var purpose = CreatePurpose(optionalEntropy);
            return provider.CreateProtector(purpose);
        }

        private IDataProtector GetMachineProtector(byte[] optionalEntropy)
        {
            var provider = DataProtectionProvider.Create(AppName);
            var purpose = CreatePurpose(optionalEntropy);
            return provider.CreateProtector(purpose);
        }

        private string CreatePurpose(byte[] optionalEntropy)
        {
            var result = BaseName + Convert.ToBase64String(optionalEntropy);
            return Uri.EscapeDataString(result);
        }
    }
}
