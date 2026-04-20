using Microsoft.Extensions.Options;
using Moq;
using OcclusionGlitch.Cryptography.Contracts.Interfaces;
using OcclusionGlitch.Cryptography.Contracts.Options;
using OcclusionGlitch.Cryptography.Services;

namespace OcclusionGlitch.Cryptography.Tests.BlindIndexTests.BaseTest;

public abstract class BlindIndexServiceTestBase
{
    // === PROPERTIES === /* */
    protected readonly Mock<IKeyProvider> _keyProviderMock;
    protected readonly Mock<IOptions<GlitchCryptOptions>> _optionsMock;
    protected readonly GlitchCryptOptions _options;
    protected readonly byte _strategyIdUnderTest;
    protected const int _base64HeaderLength = 4; // 3 bytes header -> 4 chars in Base64
    /* */

    // === CONSTRUCTORS === /* */
    protected BlindIndexServiceTestBase(byte strategyIdUnderTest)
    {
        _strategyIdUnderTest = strategyIdUnderTest;
        _keyProviderMock = new Mock<IKeyProvider>();

        _options = new GlitchCryptOptions
        {
            TargetBlindIndexStrategyId = strategyIdUnderTest,
            TargetPepperKeyVersion = 1,
            LegacyPepperKeyVersions = Array.Empty<ushort>()
        };

        // Mocking the pepper key used to strengthen the salt
        _keyProviderMock.Setup(x => x.GetPepperKey(It.IsAny<ushort>()))
            .Returns(new byte[32]);

        _optionsMock = new Mock<IOptions<GlitchCryptOptions>>();
        _optionsMock.Setup(o => o.Value).Returns(_options);
    }
    /* */

    // === METHODS === /* */
    protected virtual BlindIndexService CreateService() => new BlindIndexService(_optionsMock.Object, _keyProviderMock.Object);
    protected void SetupPepperKey(ushort version, byte[] key) => _keyProviderMock.Setup(k => k.GetPepperKey(version)).Returns(key);
    protected void AssertBlindIndexHeader(string base64Index, byte expectedStrategyId, ushort expectedKeyVersion)
    {
        var bytes = Convert.FromBase64String(base64Index);

        Assert.Equal(expectedStrategyId, bytes[0]);

        ushort actualKeyVersion = (ushort)((bytes[1] << 8) | bytes[2]);
        Assert.Equal(expectedKeyVersion, actualKeyVersion);
    }
    /* */
}