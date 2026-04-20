using Microsoft.Extensions.Options;
using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Contracts.Snapshots;
using OcclusionGlitch.Cryptography.Tests.BlindIndexTests.BaseTest;
using System.Text;

namespace OcclusionGlitch.Cryptography.Tests.BlindIndexTests.Sha256;

public class BlindIndexVersion2Sha256Test : BlindIndexServiceTestBase
{
    // === CONSTRUCTORS === /* */
    public BlindIndexVersion2Sha256Test() : base(2)
    {
        SetupPepperKey(100, Encoding.UTF8.GetBytes("super-secret-pepper-100"));
    }
    /* */

    // === TEST METHODS === /* */
    [Fact]
    public void GenerateTargetBlindIndex_ShouldReturnCorrectFormatForStrategy2()
    {
        // Arrange
        var service = CreateService();
        var plainText = "hello-world";

        // Act
        var result = service.GenerateTargetBlindIndex(plainText);

        // Assert
        Assert.NotNull(result);
        Assert.False(result.RequiresRotation);

        // Перевірка заголовка: ID має бути 2, версія 100
        AssertBlindIndexHeader(result.FullBlindIndex, _options.TargetBlindIndexStrategyId, _options.TargetPepperKeyVersion);

        // Перевірка довжини для Стратегії 2:
        // 3 байти (header) + 16 байт (hash) = 19 байт.
        // Base64 для 19 байт завжди має довжину 28 символів (включаючи padding '==')
        Assert.Equal(28, result.FullBlindIndex.Length);

        // Перевірка префіксу (перші 4 символи Base64 відповідають 3 байтам заголовка)
        Assert.Equal(result.FullBlindIndex.Substring(0, _base64HeaderLength), result.Header);
    }

    [Fact]
    public void GenerateSearchIndices_WithLegacyKeys_ShouldHandleTruncatedHash()
    {
        // Arrange
        _options.LegacyPepperKeyVersions = new ushort[] { 99, 98 };

        SetupPepperKey(_options.TargetPepperKeyVersion, Encoding.UTF8.GetBytes("pepper-1"));
        SetupPepperKey(99, Encoding.UTF8.GetBytes("pepper-99"));
        SetupPepperKey(98, Encoding.UTF8.GetBytes("pepper-98"));

        var service = CreateService();

        // Act
        var result = service.GenerateSearchIndices("some-data");

        // Assert
        Assert.Equal(3, result.AllFullIndices.Length);
        Assert.True(result.RequiresRotation);

        // Перевіряємо, що всі індекси мають довжину, відповідну 2-й стратегії (28 символів Base64)
        foreach (var snapshot in result.AllFullIndices)
            Assert.Equal(28, snapshot.FullBlindIndex.Length);

        // Пошук та валідація конкретних версій
        var targetIndex = FindSnapshotByVersion(result.AllFullIndices, _options.TargetPepperKeyVersion);
        var legacyIndex99 = FindSnapshotByVersion(result.AllFullIndices, 99);

        Assert.False(targetIndex.RequiresRotation);
        Assert.True(legacyIndex99.RequiresRotation);

        // Перевірка, що навіть у legacy індексу правильний ID стратегії (2)
        AssertBlindIndexHeader(legacyIndex99.FullBlindIndex, _options.TargetBlindIndexStrategyId, 99);
    }

    /// <summary>
    /// Допоміжний метод для пошуку Snapshot за версією ключа всередині Base64
    /// </summary>
    private BlindIndexSnapshot FindSnapshotByVersion(IEnumerable<BlindIndexSnapshot> snapshots, ushort expectedVersion)
    {
        BlindIndexSnapshot? snapshot = snapshots.FirstOrDefault(s =>
        {
            var bytes = Convert.FromBase64String(s.FullBlindIndex);
            if (bytes.Length < 3) return false;
            ushort actualVersion = (ushort)((bytes[1] << 8) | bytes[2]);
            return actualVersion == expectedVersion;
        });

        if (snapshot == null)
            throw new Exception($"Snapshot with version {expectedVersion} not found. Strategy: {_options.TargetBlindIndexStrategyId}");

        return (BlindIndexSnapshot)snapshot;
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GenerateTargetBlindIndex_ShouldThrowIfPlainTextInvalid(string invalidText)
    {
        var service = CreateService();
        Assert.Throws<GlitchCryptException>(() => service.GenerateTargetBlindIndex(invalidText));
    }
    /* */
}