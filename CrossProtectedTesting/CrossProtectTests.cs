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
            RunTrip(entropy, CrossProtectionScope.LocalMachine);
        }

        [Fact]
        public void ProtectTextMachineEntropy()
        {
            var entropy = new byte[] { 24, 76, 211, 4 };
            RunTrip(entropy, CrossProtectionScope.LocalMachine);
        }

        private void RunTrip(byte[] entropy, CrossProtectionScope scope)
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
            RunTrip(entropy, CrossProtectionScope.LocalMachine, protector);
        }

        [SkippableFact]
        public void RunTripWindowsUser()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows));
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var protector = new AspNetWrapper();
            RunTrip(entropy, CrossProtectionScope.CurrentUser, protector);
        }

        [SkippableFact]
        public void RunTripAspMachine()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows));
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var protector = new AspNetWrapper();
            RunTrip(entropy, CrossProtectionScope.LocalMachine, protector);
        }

        [SkippableFact]
        public void RunTripAspUser()
        {
            Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows));
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var protector = new DpapiWrapper();
            RunTrip(entropy, CrossProtectionScope.CurrentUser, protector);
        }

        private void RunTrip(byte[] entropy, CrossProtectionScope scope, IProtector protector)
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
            var encrypted = protector.Protect(_sampleBytes, entropy, CrossProtectionScope.CurrentUser);
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(encrypted, entropy, CrossProtectionScope.LocalMachine));
        }

        [Fact]
        public void UserCannotReadMachine()
        {
            var protector = new AspNetWrapper();
            var entropy = new byte[] { 24, 76, 211, 4, 255 };
            var encrypted = protector.Protect(_sampleBytes, entropy, CrossProtectionScope.LocalMachine);
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(encrypted, entropy, CrossProtectionScope.CurrentUser));
        }

        [Fact]
        public void DifferentEntropyFailsMachine()
        {
            var protector = new AspNetWrapper();
            var entropy1 = new byte[] { 24, 76, 211, 4, 255 };
            var entropy2 = new byte[] { 24, 76, 211, 4, 254 };
            var encrypted = protector.Protect(_sampleBytes, entropy1, CrossProtectionScope.LocalMachine);
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(encrypted, entropy2, CrossProtectionScope.LocalMachine));
        }

        [Fact]
        public void DifferentEntropyFailsUser()
        {
            var protector = new AspNetWrapper();
            var entropy1 = new byte[] { 24, 76, 211, 4, 255 };
            var entropy2 = new byte[] { 24, 76, 211, 4, 254 };
            var encrypted = protector.Protect(_sampleBytes, entropy1, CrossProtectionScope.CurrentUser);
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(encrypted, entropy2, CrossProtectionScope.CurrentUser));
        }

    }
}
