using OcclusionGlitch.Cryptography.Tests.Base;

namespace OcclusionGlitch.Cryptography.Tests.CryptTests.AesGcm;

public class CryptAesGcmV2Tests : CryptTestBase
{
    // === PROPERTIES === /* */
    public const int _currentKeySize = (256 / 8);
    /* */

    // === CONSTRUCTORS === /* */
    public CryptAesGcmV2Tests() : base(2, 1, _currentKeySize) { }
    /* */
}