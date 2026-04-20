using Microsoft.Extensions.Options;
using OcclusionGlitch.Cryptography.Contracts.Options;
using OcclusionGlitch.Cryptography.Services;
using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using OcclusionGlitch.Cryptography.Services.Internal.Providers;
using OcclusionGlitch.Cryptography.Tests.HashTests.BaseTest;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Tests.HashTests;

public class HashVersion1Pbkdf2Tests() : HashServiceVersionTestBase(1)
{
    // === TEST METHODS === /* */
    [Fact]
    public void ProviderSettings_ShouldStrictlyMatch_Strategy1_Specifications()
    {
        // Act: Отримуємо стратегію з провайдера
        var settings = HashStrategyProvider.GetStrategy(1);

        // Assert: Перевіряємо відповідність OWASP рекомендаціям для PBKDF2
        Assert.Equal(HasherEngineType.PBKDF2, settings.HashEngineType);
        Assert.Equal(HashAlgorithmName.SHA256, settings.HashAlgorithm);
        Assert.Equal(600000, settings.Iterations); // High iterations for security
        Assert.Equal(32, settings.HashSize);    // 256-bit hash
        Assert.Equal(16, settings.SaltSize);      // 128-bit salt
    }

    [Fact]
    public void GenerateTargetHash_ShouldProduceCorrectBinaryFormat_ForStrategy1()
    {
        // Arrange
        var strategy = HashStrategyProvider.GetStrategy(1);
        // Розрахунок: Header(3) + Salt(16) + Hash(32) = 51 byte
        int expectedLength = 3 + strategy.SaltSize + strategy.HashSize;

        // Act
        var result = _hashService.GenerateTargetHash("SecretPassword");
        var raw = Convert.FromBase64String(result.FullHash);

        // Assert
        Assert.Equal(expectedLength, raw.Length);
        Assert.Equal(1, raw[0]); // Strategy ID must be 1

        // Перевірка версії Pepper-ключа (TargetPepperKeyVersion = 1)
        Assert.Equal(0, raw[1]); // High byte
        Assert.Equal(1, raw[2]); // Low byte
    }

    [Fact]
    public void VerifyHash_ShouldFlagRotation_WhenSystemUpgradedToStrategy20()
    {
        // 1. Створюємо хеш через PBKDF2 (Strategy 1)
        var v1Hash = _hashService.GenerateTargetHash("Password123");

        // 2. Налаштовуємо сервіс на використання Argon2id (Strategy 20) як цільової
        var upgradedOptions = Options.Create(new GlitchCryptOptions
        {
            TargetHashStrategyId = 20,
            TargetPepperKeyVersion = 1,
            Argon2Options = new Argon2Options
            {
                MemorySizeKiB = 4096,
                Iterations = 3,
                DegreeOfParallelism = 1
            }
        });

        var upgradedService = new HashService(upgradedOptions, _keyProviderMock.Object);

        // 3. Верифікуємо старий хеш новим сервісом
        var result = upgradedService.VerifyHash("Password123", v1Hash.FullHash);

        // Assert
        Assert.True(result.IsMatch);
        // КРИТИЧНО: Має бути True, бо PBKDF2 (ID 1) застарів відносно Argon2id (ID 20)
        Assert.True(result.RequiresRotation);
    }

    [Fact]
    public void VerifyHash_ShouldFlagRotation_WhenPepperKeyVersionChanges()
    {
        // 1. Генеруємо хеш із Pepper версії 1
        var oldKeyHash = _hashService.GenerateTargetHash("Password123");

        // 2. Змінюємо в налаштуваннях цільову версію Pepper на 2
        var rotatedOptions = Options.Create(new GlitchCryptOptions
        {
            TargetHashStrategyId = 1,
            TargetPepperKeyVersion = 2
        });
        var rotatedService = new HashService(rotatedOptions, _keyProviderMock.Object);

        // 3. Верифікуємо
        var result = rotatedService.VerifyHash("Password123", oldKeyHash.FullHash);

        // Assert
        Assert.True(result.IsMatch);
        // Rotation Required, бо хоча алгоритм той самий, секрет (Pepper) було оновлено
        Assert.True(result.RequiresRotation);
    }
    /* */
}