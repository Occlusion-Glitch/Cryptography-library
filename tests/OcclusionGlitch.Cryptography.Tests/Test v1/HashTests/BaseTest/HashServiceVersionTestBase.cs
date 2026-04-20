using Microsoft.Extensions.Options;
using Moq;
using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Contracts.Interfaces;
using OcclusionGlitch.Cryptography.Contracts.Options;
using OcclusionGlitch.Cryptography.Services;

namespace OcclusionGlitch.Cryptography.Tests.HashTests.BaseTest;

public abstract class HashServiceVersionTestBase
{
    // === PROPERTIES === /* */
    public static IEnumerable<object[]> StandardTestStrings => new List<object[]>
    {
        new object[] { "SecurePassword123!" },
        new object[] { "User_Email_Example@domain.com" },
        new object[] { "Іванов Іван Іванович" }, // UTF-8 check
        new object[] { "1234-5678-9012-3456" }, // Sensitive ID check
        new object[] { "Short" }
    };

    protected readonly Mock<IKeyProvider> _keyProviderMock;
    protected readonly HashService _hashService;
    protected readonly byte _strategyIdUnderTest;
    protected const int _base64HeaderLength = 4; // 3 bytes header -> 4 chars in Base64
    /* */

    // === CONSTRUCTORS === /* */
    protected HashServiceVersionTestBase(byte strategyIdUnderTest)
    {
        _strategyIdUnderTest = strategyIdUnderTest;
        _keyProviderMock = new Mock<IKeyProvider>();

        var options = Options.Create(new GlitchCryptOptions
        {
            TargetHashStrategyId = strategyIdUnderTest,
            TargetPepperKeyVersion = 1,
            Argon2Options = new Argon2Options
            {
                MemorySizeKiB = 4096, // Small for fast tests (4MB)
                DegreeOfParallelism = 1,
                Iterations = 2
            }
        });

        // Mocking the pepper key used to strengthen the salt
        _keyProviderMock.Setup(x => x.GetPepperKey(It.IsAny<ushort>()))
            .Returns(new byte[32]);

        _hashService = new HashService(options, _keyProviderMock.Object);
    }
    /* */

    // === TEST METHODS (VALIDATION) === /* */
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GenerateTargetHash_ShouldThrow_WhenInputIsInvalid(string? invalidInput)
    {
        Assert.Throws<GlitchCryptException>(() => _hashService.GenerateTargetHash(invalidInput!));
    }

    [Fact]
    public void GenerateTargetHash_ShouldThrow_WhenKeyProviderReturnsEmptyKey()
    {
        _keyProviderMock.Setup(x => x.GetPepperKey(It.IsAny<ushort>()))
            .Returns(Array.Empty<byte>());

        Assert.Throws<GlitchCryptException>(() => _hashService.GenerateTargetHash("Valid text"));
    }

    // === TEST METHODS (PASSWORD HASHING) === /* */

    [Theory]
    [MemberData(nameof(StandardTestStrings))]
    public void GenerateTargetHash_ShouldBeProbabilistic(string input)
    {
        // Act: Generate two hashes for the same input
        var result1 = _hashService.GenerateTargetHash(input);
        var result2 = _hashService.GenerateTargetHash(input);

        // Assert: Argon2id MUST produce different results due to random salt
        Assert.NotEqual(result1.FullHash, result2.FullHash);

        // Metadata must be the same (Strategy and Key Version)
        Assert.Equal(result1.Header, result2.Header);
        Assert.Equal(_base64HeaderLength, result1.Header.Length);
    }

    [Theory]
    [MemberData(nameof(StandardTestStrings))]
    public void VerifyHash_ShouldReturnTrue_ForValidInput(string input)
    {
        // Arrange
        var hashResult = _hashService.GenerateTargetHash(input);

        // Act
        var verifyResult = _hashService.VerifyHash(input, hashResult.FullHash);

        // Assert
        Assert.True(verifyResult.IsMatch);
        Assert.False(verifyResult.RequiresRotation);
        Assert.Equal(hashResult.Header, verifyResult.Header);
    }

    [Theory]
    [MemberData(nameof(StandardTestStrings))]
    public void VerifyHash_ShouldReturnFalse_ForIncorrectInput(string input)
    {
        // Arrange
        var hashResult = _hashService.GenerateTargetHash(input);

        // Act
        var verifyResult = _hashService.VerifyHash("Incorrect_Password_Value", hashResult.FullHash);

        // Assert
        Assert.False(verifyResult.IsMatch);
    }

    [Fact]
    public void VerifyHash_ShouldThrow_WhenPackageIsMalformed()
    {
        // Act & Assert
        Assert.Throws<GlitchCryptException>(() => _hashService.VerifyHash("test", "NotBase64!!!"));

        // Header too short (need at least 3 bytes)
        string tooShort = Convert.ToBase64String(new byte[] { 1, 0 });
        Assert.Throws<GlitchCryptException>(() => _hashService.VerifyHash("test", tooShort));
    }

    [Fact]
    public void VerifyHash_ShouldReturnFalse_WhenHashDataIsTampered()
    {
        // Arrange
        var hashResult = _hashService.GenerateTargetHash("SensitiveData");
        byte[] raw = Convert.FromBase64String(hashResult.FullHash);

        // Act: Flip a bit in the actual hash content (after metadata)
        raw[raw.Length - 1] ^= 0x01;
        var tampered = Convert.ToBase64String(raw);

        // Assert
        var verifyResult = _hashService.VerifyHash("SensitiveData", tampered);
        Assert.False(verifyResult.IsMatch);
    }
    /* */
}