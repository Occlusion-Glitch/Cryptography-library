using OcclusionGlitch.Cryptography.Tests.Base;

namespace OcclusionGlitch.Cryptography.Tests.CryptTests.AesGcm;

public class CryptAesGcmV1Tests : CryptTestBase
{
    // === PROPERTIES === /* */
    public const int _currentKeySize = (128 / 8);
    /* */

    // === CONSTRUCTORS === /* */
    public CryptAesGcmV1Tests() : base(1, 1, _currentKeySize) { }
    /* */
}