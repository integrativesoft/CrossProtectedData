/*
Copyright (c) 2020 Integrative Software LLC
Created: 1/2020
MIT License
Author: Pablo Carbonell
*/

using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CrossProtectedData
{
    interface IProtector
    {
        byte[] Protect(byte[] userData, byte[] optionalEntrypy, DataProtectionScope scope);
        byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope);
    }

    public static class CrossProtect
    {
        readonly static IProtector _protector = CreateProtector();

        private static IProtector CreateProtector()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new DpapiWrapper();
            }
            else
            {
                return new AspNetWrapper();
            }
        }

        public static byte[] Protect(byte[] userData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            return _protector.Protect(userData, optionalEntropy, scope);
        }

        public static byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            return _protector.Unprotect(encryptedData, optionalEntropy, scope);
        }
    }
}
