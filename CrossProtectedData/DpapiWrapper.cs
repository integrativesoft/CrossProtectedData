/*
Copyright (c) 2020 Integrative Software LLC
Created: 1/2020
MIT License
Author: Pablo Carbonell
*/

using System.Security.Cryptography;

namespace CrossProtectedData
{
    sealed class DpapiWrapper : IProtector
    {
        public byte[] Protect(byte[] userData, byte[] optionalEntrypy, DataProtectionScope scope)
        {
            return ProtectedData.Protect(userData, optionalEntrypy, scope);
        }

        public byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            return ProtectedData.Unprotect(encryptedData, optionalEntropy, scope);
        }
    }
}
