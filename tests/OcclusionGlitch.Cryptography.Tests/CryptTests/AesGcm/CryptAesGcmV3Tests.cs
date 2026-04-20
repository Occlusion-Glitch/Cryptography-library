using OcclusionGlitch.Cryptography.Tests.Base;

namespace OcclusionGlitch.Cryptography.Tests.CryptTests.AesGcm;

public class CryptAesGcmV3Tests : CryptTestBase
{
    // === PROPERTIES === /* */
    public const int _currentKeySize = (256 / 8);
    /* */

    // === CONSTRUCTORS === /* */
    public CryptAesGcmV3Tests() : base(3, 1, _currentKeySize) { }
    /* */
}