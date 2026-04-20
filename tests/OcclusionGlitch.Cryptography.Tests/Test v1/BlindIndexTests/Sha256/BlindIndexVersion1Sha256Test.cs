using Microsoft.Extensions.Options;
using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Contracts.Snapshots;
using OcclusionGlitch.Cryptography.Tests.BlindIndexTests.BaseTest;
using System.Text;

namespace OcclusionGlitch.Cryptography.Tests.BlindIndexTests.Sha256;

public class BlindIndexVersion1Sha256Test: BlindIndexServiceTestBase
{
    // === CONSTRUCTORS === /* */
    public BlindIndexVersion1Sha256Test() : base(1)
    {
        SetupPepperKey(100, Encoding.UTF8.GetBytes("super-secret-pepper-100"));
    }
    /* */

    // === TEST METHODS === /* */
    [Fact]
    public void GenerateTargetBlindIndex_ShouldReturnCorrectFormat()
    {
        // Arrange
        var service = CreateService();
        var plainText = "hello-world";

        // Act
        var result = service.GenerateTargetBlindIndex(plainText);

        // Assert
        Assert.NotNull(result);
        Assert.False(result.RequiresRotation);
        AssertBlindIndexHeader(result.FullBlindIndex, _options.TargetBlindIndexStrategyId, 1);

        // Перевірка префіксу (перші 4 символи Base64 для 3 байтів заголовка)
        Assert.Equal(result.FullBlindIndex.Substring(0, _base64HeaderLength), result.Header);
    }

    [Fact]
    public void GenerateSearchIndices_WithLegacyKeys_ShouldReturnMultipleIndices()
    {
        // Arrange
        _options.TargetPepperKeyVersion = 100;
        _options.LegacyPepperKeyVersions = new ushort[] { 99, 98 };

        SetupPepperKey(100, Encoding.UTF8.GetBytes("pepper-100"));
        SetupPepperKey(99, Encoding.UTF8.GetBytes("pepper-99"));
        SetupPepperKey(98, Encoding.UTF8.GetBytes("pepper-98"));

        var service = CreateService();

        // Act
        var result = service.GenerateSearchIndices("some-data");

        // Assert
        Assert.Equal(3, result.AllFullIndices.Length);
        Assert.True(result.RequiresRotation);

        // Шукаємо конкретні версії, розкодовуючи заголовок
        var targetIndex = FindSnapshotByVersion(result.AllFullIndices, 100);
        var legacyIndex99 = FindSnapshotByVersion(result.AllFullIndices, 99);
        var legacyIndex98 = FindSnapshotByVersion(result.AllFullIndices, 98);

        Assert.False(targetIndex.RequiresRotation);
        Assert.True(legacyIndex99.RequiresRotation);
        Assert.True(legacyIndex98.RequiresRotation);

        // Додатково перевіряємо заголовок через базовий метод
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
            throw new Exception($"Snapshot with version {expectedVersion} not found in the result.");

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
}