# CrossProtectedData

A DataProtect wrapper that uses DPAPI in Windows and AspNetCore.DataProtection in non-Windows platforms.

This library offers the same interface as the `ProtectedData` class which uses DPAPI and works in Windows only.
- When running in Windows, it calls the ProtectedData class.
- When running in non-Windows, it uses instead AspNetCore.DataProtection

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
