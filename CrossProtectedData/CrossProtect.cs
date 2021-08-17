/*
Copyright (c) 2020 Integrative Software LLC
Created: 1/2020
MIT License
Author: Pablo Carbonell
*/

using System.Runtime.InteropServices;

namespace Integrative.Encryption
{
    public enum CrossProtectionScope
    {
        //
        // Summary:
        //     The protected data is associated with the current user. Only threads running
        //     under the current user context can unprotect the data.
        CurrentUser = 0,
        //
        // Summary:
        //     The protected data is associated with the machine context. Any process running
        //     on the computer can unprotect data. This enumeration value is usually used in
        //     server-specific applications that run on a server where untrusted users are not
        //     allowed access.
        LocalMachine = 1
    }

    interface IProtector
    {
        byte[] Protect(byte[] userData, byte[] optionalEntrypy, CrossProtectionScope scope);
        byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, CrossProtectionScope scope);
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

        public static byte[] Protect(byte[] userData, byte[] optionalEntropy, CrossProtectionScope scope)
        {
            return _protector.Protect(userData, optionalEntropy, scope);
        }

        public static byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, CrossProtectionScope scope)
        {
            return _protector.Unprotect(encryptedData, optionalEntropy, scope);
        }
    }
}
