# CrossProtectedData

A replacement for the `ProtectedData` class in NET Standard that works not only in Windows but also Linux/MacOS/others.

This library is a wrapper of `ProtectedData` and exposes the same interface. The difference is the following:
- When running in Windows, it calls directly the original ProtectedData class supported in Windows.
- When running in non-Windows, it implement those calls using instead the AspNetCore.DataProtection library.

There is no need to download this repository. This library is available as a [NuGet package](https://www.nuget.org/packages/Integrative.CrossProtect/).
# Example

```csharp
using Integrative.Encryption;
using System;
using System.Security.Cryptography;
using System.Text;

namespace CrossProtectedExample
{
    class Program
    {
        static void Main(string[] args)
        {
            // our text to protect
            var text = "Hello!";

            // get bytes from text
            var bytes = Encoding.UTF8.GetBytes(text);

            // optional entropy
            var entropy = new byte[] { 100, 25, 31, 213 };

            // protect (encrypt)
            var protectedBytes = CrossProtect.Protect(bytes, entropy,
                DataProtectionScope.CurrentUser);

            // unprotect (decrypt)
            var unprotected = CrossProtect.Unprotect(protectedBytes, entropy,
                DataProtectionScope.CurrentUser);

            // convert bytes back to text
            var result = Encoding.UTF8.GetString(unprotected);

            // print result
            Console.WriteLine(result);
            Console.ReadKey();
        }
    }
}
```
