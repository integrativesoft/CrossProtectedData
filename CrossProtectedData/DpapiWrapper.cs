/*
Copyright (c) 2020 Integrative Software LLC
Created: 1/2020
MIT License
Author: Pablo Carbonell
*/

using System.Security.Cryptography;

namespace Integrative.Encryption
{
    sealed class DpapiWrapper : IProtector
    {
        public byte[] Protect(byte[] userData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            return ProtectedData.Protect(userData, optionalEntropy, scope);
        }

        public byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, DataProtectionScope scope)
        {
            return ProtectedData.Unprotect(encryptedData, optionalEntropy, scope);
        }
    }
}
