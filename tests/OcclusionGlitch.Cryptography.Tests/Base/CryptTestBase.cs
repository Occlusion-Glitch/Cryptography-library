using Microsoft.Extensions.Options;
using Moq;
using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Contracts.Interfaces;
using OcclusionGlitch.Cryptography.Contracts.Options;
using OcclusionGlitch.Cryptography.Services;
using OcclusionGlitch.Cryptography.Services.Internal.Providers;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;

namespace OcclusionGlitch.Cryptography.Tests.Base;

public abstract class CryptTestBase
{
    /* Base class for all cryptographic tests.
     * Pacakge structure: [strategyId (1 byte)] [key version (2 bytes)] [salt] [nonce] [tag] [cipher text]
     * Ciptext is Base64-encoded and includes the header (strategy ID and key version) for validation during decryption.
     * Max of cipher text length is not strictly defined, but it should be at least long enough to contain the header, salt, nonce, and tag for the given strategy.
     */
    // === PROPERTIES === /* */
    // === PROPERTIES (CONSTANTS) ===
    protected const int _base64HeaderOffset = 4; // Base64 encoding expands data
    protected const int _bytesHeaderOffset = 3; // Number of bytes used for strategy ID and key version in the package header
    // === PROPERTIES (GENERAL) ===
    protected readonly byte _defaultStrategyId; // Default strategy ID for tests
    internal readonly CryptStrategySnapshot _cryptStrategySnapshot;
    protected readonly ushort _defaultKeyVersionDefault; // Default key version for tests
    protected readonly GlitchCryptOptions _options;
    protected readonly CryptService _defaultCryptService;
    // === PROPERTIES (MOCKS) ===
    protected readonly Mock<IKeyProvider> _defaultKeyProviderMock;
    protected readonly Mock<IOptions<GlitchCryptOptions>> _defaultOptionsMock;
    #region === PROPERTIES (INPUT DATA) ===
    public static IEnumerable<object[]> ValidPlainTexts => new List<object[]>
    {
        // --- BASIC AND BOUNDARY LENGTHS ---
        new object[] { "A", "user-id-001" },                                     // Min length
        new object[] { " ", "context-empty-space" },                             // Whitespace
        new object[] { new string('X', 1024), "doc-type-standard" },             // 1 KB
        new object[] { new string('B', 10000), "system-logs-batch" },            // 10 KB
        // --- LARGE DATA (1 MB+) ---
        new object[] { new string('M', 1024 * 1024), "large-blob-id-99" },       // 1 MB ASCII
        new object[] { string.Concat(Enumerable.Repeat("🚀", 256 * 1024)), "emoji-storage" }, // 1 MB UTF-8
        new object[] { new string(' ', 1024 * 1024), "padding-test" },           // 1 MB Whitespace
        // --- UNICODE AND MULTIBYTE CHARACTERS ---
        new object[] { "Привіт, Світе!", "lang-ua" },                             // Cyrillic
        new object[] { "你好，世界", "lang-ch" },                                  // Chinese
        new object[] { "नमस्ते दुनिया", "lang-hi" },                                  // Hindi
        new object[] { "مرحبا بالعالم", "direction-rtl" },                        // Arabic
        new object[] { "שָׁלוֹם", "context-hebrew" },                               // Hebrew
        // --- NORMALIZATION (NFC vs NFD) ---
        // Для однакових текстів у різних формах нормалізації ми використовуємо однакове AD
        new object[] { "\u0439", "norm-test-i" },                                // 'й' (NFC)
        new object[] { "\u0438\u0306", "norm-test-i" },                          // 'и' + '◌̆' (NFD)
        new object[] { "é", "norm-test-e" },                                     // 'é'
        new object[] { "e\u0301", "norm-test-e" },                               // 'e' + '◌́'
        // --- SPECIAL CHARACTERS AND EMOJIS ---
        new object[] { "🚀🔥💻", "social-media-post" },                           // Surrogate pairs
        new object[] { "Zero\0Width\u200BSpace", "binary-edge-case" },           // Null-terminators
        new object[] { "\u202Ereversed", "security-bidi-test" },                 // Bidi Override
        new object[] { "~!@#$%^&*()_+`1234567890-={}|[]\\:\"<>?,./", "all-symbols" },
        // --- STRUCTURED FORMATS (JSON, XML, SQL) ---
        new object[] { "{\"id\":123,\"name\":\"John\"}", "application/json" },   // JSON
        new object[] { "<user id='1'>Content</user>", "application/xml" },        // XML
        new object[] { "SELECT * FROM Users;", "query-metadata" },               // SQL
        new object[] { "https://example.com/api", "url-endpoint" },               // URL
        // --- WHITESPACE AND CONTROL CHARACTERS ---
        new object[] { "\t\t\n\r  Text with breaks  \n", "formatting-test" },    // Control chars
        new object[] { new string('\u0001', 100), "low-level-ctrl" },            // Non-printable
        new object[] { "   ", "only-spaces" },                                   // Spaces
        // --- EDGE CASE: ASSOCIATED DATA VARIATIONS ---
        new object[] { "SameText", "" },                                         // Empty AD
        new object[] { "SameText", "Special-AD-Value" },                         // Same text, different AD
        new object[] { "DataWithLongAD", new string('A', 512) }                  // Very long AD
    };
    public static IEnumerable<object[]> InvalidPlainTexts => new List<object[]>
    {
        // --- NULL AND EMPTY STRINGS ---
        new object[] {null!},                                       // Null string
        new object[] {""},                                          // Empty string
    };
    public static IEnumerable<object[]> InvalidCipherTexts => new List<object[]>
    {
        // --- NULL, EMPTY ---
        new object[] {null!},                                        // Null string
        new object[] {""},                                           // Empty string
        // --- WHITESPACE ONLY ---
        new object[] {"   "},                                        // Only whitespace
        // --- INVALID BASE64 ---
        new object[] {"NotBase64!"},                                // Invalid Base64 characters
        // --- VALID BASE64 BUT INVALID PACKAGE STRUCTURE ---
        new object[] {"SGVsbG8gV29ybGQ"},                           // Valid Base64 but not a valid package (missing padding)
        new object[] {"SGVsbG8gV29ybGQ="},                          // Valid Base64 but not a valid package (too short)
        new object[] {"SGVsbG8gV29ybGQ=="},                         // Valid Base64 but not a valid package (too short)
    };
    #endregion
    /* */

    // === CONSTRUCTORS === /* */
    protected CryptTestBase(byte strategyId, ushort keyVersion, int keySize)
    {
        // Initialize default strategy ID and key version for tests
        _defaultStrategyId = strategyId;
        _cryptStrategySnapshot = CryptStrategyProvider.GetStrategy(strategyId);
        _defaultKeyVersionDefault = keyVersion;
        _options = new GlitchCryptOptions
        {
            TargetCryptStrategyId = strategyId,
            TargetCryptKeyVersion = keyVersion,
        };

        // Mocking the options and key provider for tests
        _defaultOptionsMock = new Mock<IOptions<GlitchCryptOptions>>();
        _defaultOptionsMock.Setup(o => o.Value).Returns(_options);
        _defaultKeyProviderMock = new Mock<IKeyProvider>();
        _defaultKeyProviderMock.Setup(x => x.GetCryptKey(It.IsAny<ushort>())).Returns(new byte[keySize]);

        // Create an instance of the CryptService with mocked dependencies
        _defaultCryptService = new CryptService(_defaultOptionsMock.Object, _defaultKeyProviderMock.Object);
    }
    /* */

    // === METHODS (HELPERS) === /* */
    // Helper methods to validate package structure and content
    protected bool IsPackageMinLengthValid(string cipherText, int saltSize, int nonceSize, int tagSize)
    {
        var (isValid, fullPackage) = FromBase64String(cipherText);
        if (!isValid) return false;

        // Check if the package is long enough to contain the header
        int minLength = _base64HeaderOffset + saltSize + nonceSize + tagSize;
        return fullPackage.Length >= minLength;
    }
    // Helper method to validate the package header (strategy ID and key version)
    protected bool IsPackageHeaderValid(string cipherTextBase64, byte strategyId, ushort keyVersion)
    {
        var (isValid, fullPackage) = FromBase64String(cipherTextBase64);
        if (!isValid) return false;

        // Check if the package is long enough to contain the header
        if (fullPackage.Length < _base64HeaderOffset) return false;

        // Check strategy ID and key version
        ushort _keyVersion = (ushort)((fullPackage[1] << 8) | fullPackage[2]);
        return fullPackage[0] == strategyId && _keyVersion == keyVersion;
    }
    // Helper method to create an instance of the CryptService with mocked dependencies
    protected CryptService GetCryptService(IOptions<GlitchCryptOptions> options, IKeyProvider keyProvider) => new CryptService(options, keyProvider);
    // Helper method to decode Base64 and handle exceptions gracefully
    protected (bool, byte[]) FromBase64String(string base64)
    {
        try { return (true, Convert.FromBase64String(base64)); }
        catch { }

        return (false, Array.Empty<byte>());
    }
    // Helper method to generate a large string of specified size in megabytes (for performance testing)
    protected string GenerateLargeString(int sizeInMb)
    {
        char[] chars = new char[sizeInMb * 1024 * 1024 / 2];
        Array.Fill(chars, 'A');
        return new string(chars);
    }
    /* */

    // === TESTS === /* */
    #region === TESTS (GENERAL ENCRYPTION) === /* */
    // === TESTS (ENCRYPTION VALID EXPECTATIONS) ===
    [Theory]
    [MemberData(nameof(ValidPlainTexts))]
    // Перевірка що шифрування валідного plain text генерує пакет, який відповідає мінімальним вимогам до структури (header + salt + nonce + tag)
    public void Encrypt_ShouldProduceValidPackage_WhenPlainTextIsValid(string plainText, string associatedData)
    {
        try
        {
            // Encrypt the plain text and get the cipher result
            var cipherResult = _defaultCryptService.EncryptTarget(plainText);

            // Act
            string cipherText = cipherResult.FullCipher;
            Assert.NotEmpty(cipherText);
            if (!IsPackageMinLengthValid(cipherText, _cryptStrategySnapshot.SaltSize, _cryptStrategySnapshot.NonceSize, _cryptStrategySnapshot.TagSize))
                Assert.Fail("Cipher text does not meet minimum length requirements for a valid package.");
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    [Theory]
    [MemberData(nameof(ValidPlainTexts))]
    // Перевірка що шифрування валідного plain text з associated data генерує пакет, який відповідає мінімальним вимогам до структури (header + salt + nonce + tag)
    public void Encrypt_ShouldProduceValidPackage_WhenPlainTextIsValid_WithAssociatedData(string plainText, string associatedData)
    {
        try
        {
            // Encrypt the plain text and get the cipher result
            var cipherResult = _defaultCryptService.EncryptTarget(plainText, associatedData!);

            // Act
            string cipherText = cipherResult.FullCipher;
            Assert.NotEmpty(cipherText);
            if (!IsPackageMinLengthValid(cipherText, _cryptStrategySnapshot.SaltSize, _cryptStrategySnapshot.NonceSize, _cryptStrategySnapshot.TagSize))
                Assert.Fail("Cipher text does not meet minimum length requirements for a valid package.");
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    [Theory]
    [MemberData(nameof(ValidPlainTexts))]
    // Перевірка що шифрування валідного plain text генерує пакет, який містить правильний header з очікуваним strategy ID та key version
    public void Encrypt_ShouldIncludeCorrectHeader_WhenPlainTextIsValid(string plainText, string associatedData)
    {
        try
        {
            // Encrypt the plain text and get the cipher result
            var cipherResult = _defaultCryptService.EncryptTarget(plainText!);

            // Act
            string cipherText = cipherResult.FullCipher;
            Assert.NotEmpty(cipherText);
            if (!IsPackageHeaderValid(cipherText, _defaultStrategyId, _defaultKeyVersionDefault))
                Assert.Fail("Cipher text header does not contain the expected strategy ID and key version.");
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    [Theory]
    [MemberData(nameof(ValidPlainTexts))]
    // Перевірка що шифрування валідного plain text з associated data генерує пакет, який містить правильний header з очікуваним strategy ID та key version
    public void Encrypt_ShouldIncludeCorrectHeader_WhenPlainTextIsValid_WithAssociatedData(string plainText, string associatedData)
    {
        try
        {
            // Encrypt the plain text and get the cipher result
            var cipherResult = _defaultCryptService.EncryptTarget(plainText!, associatedData!);
            // Act
            string cipherText = cipherResult.FullCipher;
            Assert.NotEmpty(cipherText);
            if (!IsPackageHeaderValid(cipherText, _defaultStrategyId, _defaultKeyVersionDefault))
                Assert.Fail("Cipher text header does not contain the expected strategy ID and key version.");
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    [Fact]
    // Перевірка що шифрування одного і того ж plain text двічі генерує різні cipher text (через випадковість salt та nonce), але з однаковим header
    public void Encrypt_ShouldProduceDifferentCipherTexts_ForSamePlainText()
    {
        // Plain texts for testing
        string plainText = "Same plain text";

        try
        {
            var cipherResult1 = _defaultCryptService.EncryptTarget(plainText);
            var cipherResult2 = _defaultCryptService.EncryptTarget(plainText);

            // Act
            Assert.NotEqual(cipherResult1.FullCipher, cipherResult2.FullCipher);
            Assert.Equal(cipherResult1.Header, cipherResult2.Header); // Header should be the same since strategy ID and key version are the same
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    [Fact]
    // Перевірка що шифрування одного і того ж plain text з однаковим associated data двічі генерує різні cipher text (через випадковість salt та nonce), але з однаковим header
    public void Encrypt_ShouldProduceDifferentCipherTexts_ForSamePlainTextAndAssociatedData()
    {
        // Plain text and associated data for testing
        string plainText = "Same plain text";
        string associatedData = "Same associated data";
        try
        {
            var cipherResult1 = _defaultCryptService.EncryptTarget(plainText, associatedData);
            var cipherResult2 = _defaultCryptService.EncryptTarget(plainText, associatedData);
            // Act
            Assert.NotEqual(cipherResult1.FullCipher, cipherResult2.FullCipher);
            Assert.Equal(cipherResult1.Header, cipherResult2.Header); // Header should be the same since strategy ID and key version are the same
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    [Fact]
    // Перевірка що шифрування різних plain text генерує різні cipher text, але з однаковим header
    public void Encrypt_ShouldProduceDifferentCipherTexts_ForDifferentPlainTexts()
    {
        // Plain texts for testing
        string plainText1 = "Same plain text 1";
        string plainText2 = "Same plain text 2";

        try
        {
            var cipherResult1 = _defaultCryptService.EncryptTarget(plainText1);
            var cipherResult2 = _defaultCryptService.EncryptTarget(plainText2);

            // Act
            Assert.NotEqual(cipherResult1.FullCipher, cipherResult2.FullCipher);
            Assert.Equal(cipherResult1.Header, cipherResult2.Header); // Header should be the same since strategy ID and key version are the same
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    [Fact]
    // Перевірка що шифрування різних plain text з різним associated data генерує різні cipher text, але з однаковим header
    public void Encrypt_ShouldProduceDifferentCipherTexts_ForDifferentPlainTextAndDifferentAssociatedData()
    {
        // Plain texts for testing
        string plainText1 = "Same plain text 1";
        string associatedData1 = "associated-data-1";
        string plainText2 = "Same plain text 2";
        string associatedData2 = "associated-data-2";

        try
        {
            var cipherResult1 = _defaultCryptService.EncryptTarget(plainText1, associatedData1);
            var cipherResult2 = _defaultCryptService.EncryptTarget(plainText2, associatedData2);

            // Act
            Assert.NotEqual(cipherResult1.FullCipher, cipherResult2.FullCipher);
            Assert.Equal(cipherResult1.Header, cipherResult2.Header); // Header should be the same since strategy ID and key version are the same
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    [Fact]
    // Перевірка що шифрування різних plain text з однаковим associated data генерує різні cipher text, але з однаковим header
    public void Encrypt_ShouldProduceDifferentCipherTexts_ForDifferentPlainTextAndSameAssociatedData()
    {
        // Plain texts for testing
        string associatedData = "associated-data-1";
        string plainText1 = "Same plain text 1";
        string plainText2 = "Same plain text 2";

        try
        {
            var cipherResult1 = _defaultCryptService.EncryptTarget(plainText1, associatedData);
            var cipherResult2 = _defaultCryptService.EncryptTarget(plainText2, associatedData);

            // Act
            Assert.NotEqual(cipherResult1.FullCipher, cipherResult2.FullCipher);
            Assert.Equal(cipherResult1.Header, cipherResult2.Header); // Header should be the same since strategy ID and key version are the same
        }
        catch (Exception ex) { Assert.Fail($"Encryption threw an unexpected exception: {ex.Message}"); }
    }

    // === TESTS (ENCRYPTION INVALID EXPECTATIONS) ===
    [Theory]
    [MemberData(nameof(InvalidPlainTexts))]
    // Перевірка що шифрування невалідного plain text (null, empty, whitespace) викликає GlitchCryptException
    public void Encrypt_ShouldThrowException_WhenPlainTextIsInvalid(string? invalidText)
    {
        // Act & Assert
        Assert.Throws<GlitchCryptException>(() => _defaultCryptService.EncryptTarget(invalidText!));
    }
    #endregion /* */
    /* */
}