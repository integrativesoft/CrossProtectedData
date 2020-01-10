/*
Copyright (c) 2020 Integrative Software LLC
Created: 1/2020
MIT License
Author: Pablo Carbonell
*/

using Integrative.Encryption;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace CrossProtectedTesting
{
    public class CrossProtectTests
    {
        private const string SampleText = "hello~&*(ñ";

        readonly byte[] _sampleBytes = Encoding.UTF8.GetBytes(SampleText);

        [Fact]
        public void ProtectTextMachineNoEntropy()
        {
            var entropy = Array.Empty<byte>();
            RunTrip(entropy, DataProtectionScope.LocalMachine);
        }

        [Fact]
        public void ProtectTextMachineEntropy()
        {
            var entropy = new byte[] { 24, 76, 211, 4 };
            RunTrip(entropy, DataProtectionScope.LocalMachine);
        }

        private void RunTrip(byte[] entropy, DataProtectionScope scope)
        {
            var encrypted = CrossProtect.Protect(_sampleBytes, entropy, scope);
            var unencrypted = CrossProtect.Unprotect(encrypted, entropy, scope);
            var result = Encoding.UTF8.GetString(unencrypted);
            Assert.Equal(SampleText, result);
        }

        [SkippableFact]
        public void RunTripWindowsMachine()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows));
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var protector = new DpapiWrapper();
            RunTrip(entropy, DataProtectionScope.LocalMachine, protector);
        }

        [SkippableFact]
        public void RunTripWindowsUser()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows));
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var protector = new AspNetWrapper();
            RunTrip(entropy, DataProtectionScope.CurrentUser, protector);
        }

        [SkippableFact]
        public void RunTripAspMachine()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows));
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var protector = new AspNetWrapper();
            RunTrip(entropy, DataProtectionScope.LocalMachine, protector);
        }

        [SkippableFact]
        public void RunTripAspUser()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows));
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var protector = new DpapiWrapper();
            RunTrip(entropy, DataProtectionScope.CurrentUser, protector);
        }

        private void RunTrip(byte[] entropy, DataProtectionScope scope, IProtector protector)
        {
            var encrypted = protector.Protect(_sampleBytes, entropy, scope);
            var unencrypted = protector.Unprotect(encrypted, entropy, scope);
            var result = Encoding.UTF8.GetString(unencrypted);
            Assert.Equal(SampleText, result);
        }

        [Fact]
        public void MachineCannotReadUser()
        {
            var protector = new AspNetWrapper();
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var encrypted = protector.Protect(_sampleBytes, entropy, DataProtectionScope.CurrentUser);
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(encrypted, entropy, DataProtectionScope.LocalMachine));
        }

        [Fact]
        public void UserCannotReadMachine()
        {
            var protector = new AspNetWrapper();
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var encrypted = protector.Protect(_sampleBytes, entropy, DataProtectionScope.LocalMachine);
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(encrypted, entropy, DataProtectionScope.CurrentUser));
        }

        [Fact]
        public void DifferentEntropyFailsMachine()
        {
            var protector = new AspNetWrapper();
            var entropy1 = new byte[] { 24, 76, 211, 4, 255 };
            var entropy2 = new byte[] { 24, 76, 211, 4, 254 };
            var encrypted = protector.Protect(_sampleBytes, entropy1, DataProtectionScope.LocalMachine);
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(encrypted, entropy2, DataProtectionScope.LocalMachine));
        }

        [Fact]
        public void DifferentEntropyFailsUser()
        {
            var protector = new AspNetWrapper();
            var entropy1 = new byte[] { 24, 76, 211, 4, 255 };
            var entropy2 = new byte[] { 24, 76, 211, 4, 254 };
            var encrypted = protector.Protect(_sampleBytes, entropy1, DataProtectionScope.CurrentUser);
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(encrypted, entropy2, DataProtectionScope.CurrentUser));
        }

    }
}
