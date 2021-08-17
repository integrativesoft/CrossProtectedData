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
        public byte[] Protect(byte[] userData, byte[] optionalEntropy, CrossProtectionScope scope)
        {
            return ProtectedData.Protect(userData, optionalEntropy, (DataProtectionScope)scope);
        }

        public byte[] Unprotect(byte[] encryptedData, byte[] optionalEntropy, CrossProtectionScope scope)
        {
            return ProtectedData.Unprotect(encryptedData, optionalEntropy, (DataProtectionScope)scope);
        }
    }
}
