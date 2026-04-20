using OcclusionGlitch.Cryptography.Tests.Base;

namespace OcclusionGlitch.Cryptography.Tests.CryptTests.AesGcm;

public class CryptChaCha20V20Tests : CryptTestBase
{
    // === PROPERTIES === /* */
    public const int _currentKeySize = (256 / 8);
    /* */

    // === CONSTRUCTORS === /* */
    public CryptChaCha20V20Tests() : base(20, 1, _currentKeySize) { }
    /* */
}