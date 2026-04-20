using Microsoft.Extensions.Options;
using OcclusionGlitch.Cryptography.Contracts.Options;
using OcclusionGlitch.Cryptography.Services;
using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using OcclusionGlitch.Cryptography.Services.Internal.Providers;
using OcclusionGlitch.Cryptography.Tests.HashTests.BaseTest;
using Xunit;

namespace OcclusionGlitch.Cryptography.Tests.HashTests.Argon2;

/// <summary>
/// Tests for Strategy ID 20: Argon2id. 
/// This is the most secure hashing strategy in the system.
/// </summary>
public class HashVersion20Argon2Tests : HashServiceVersionTestBase
{
    // === CONSTRUCTOR === /* */
    public HashVersion20Argon2Tests() : base(20) { }
    /* */

    // === TEST METHODS === /* */
    [Fact]
    public void ProviderSettings_ShouldStrictlyMatch_Strategy20_Specifications()
    {
        // Act
        var strategy = HashStrategyProvider.GetStrategy(20);

        // Assert: Перевірка Argon2id (пам'ять, ітерації, паралелізм)
        Assert.Equal(HasherEngineType.Argon2id, strategy.HashEngineType);
        Assert.Equal(3, strategy.Iterations);
        Assert.Equal(32, strategy.HashSize); // 256 / 8
        Assert.Equal(16, strategy.SaltSize); // 128 / 8

        // Перевірка специфічних параметрів Argon2id
        Assert.NotNull(strategy.Argon2);
        Assert.Equal(32768, strategy.Argon2.Value.MemorySizeKb); // 32 MiB
        Assert.Equal(1, strategy.Argon2.Value.Parallelism);
        Assert.Equal(3, strategy.Argon2.Value.Iterations);
    }

    [Fact]
    public void GenerateTargetHash_ShouldProduceCorrectBinaryFormat_ForStrategy20()
    {
        // Arrange
        var strategy = HashStrategyProvider.GetStrategy(20);
        // Header(3) + Salt(16) + Hash(32) = 51 byte
        int expectedLength = 3 + strategy.SaltSize + strategy.HashSize;

        // Act
        var result = _hashService.GenerateTargetHash("Argon2_Test_Password");
        var raw = Convert.FromBase64String(result.FullHash);

        // Assert
        Assert.Equal(expectedLength, raw.Length);
        Assert.Equal(20, raw[0]); // Strategy ID byte
        Assert.Equal(0, raw[1]);  // Key Version High
        Assert.Equal(1, raw[2]);  // Key Version Low
    }

    [Fact]
    public void VerifyHash_ShouldNotRequireRotation_WhenUsingCurrentVersion()
    {
        // Arrange
        var input = "Current_Password";

        // Act
        var hashResult = _hashService.GenerateTargetHash(input);
        var verifyResult = _hashService.VerifyHash(input, hashResult.FullHash);

        // Assert: Оскільки дані та сервіс використовують ID 20, ротація не потрібна
        Assert.True(verifyResult.IsMatch);
        Assert.False(verifyResult.RequiresRotation);
        Assert.Equal(hashResult.Header, verifyResult.Header);
    }

    [Fact]
    public void VerifyHash_ShouldFlagRotation_WhenPepperKeyVersionIsOutdated()
    {
        // 1. Шифруємо поточною стратегією ID 20 та версією Pepper 1
        var v1Hash = _hashService.GenerateTargetHash("SecurityFirst");

        // 2. Створюємо сервіс, де Pepper ротований до версії 2
        var rotatedOptions = Options.Create(new GlitchCryptOptions
        {
            TargetHashStrategyId = 20,
            TargetPepperKeyVersion = 2,
            Argon2Options = new Argon2Options
            {
                MemorySizeKiB = 4096,
                Iterations = 2,
                DegreeOfParallelism = 1
            }
        });

        var rotatedService = new HashService(rotatedOptions, _keyProviderMock.Object);

        // 3. Верифікуємо
        var result = rotatedService.VerifyHash("SecurityFirst", v1Hash.FullHash);

        // Assert
        Assert.True(result.IsMatch);

        // КРИТИЧНО: Навіть якщо алгоритм той самий, зміна Pepper (секрету)
        // має сигналізувати про потребу оновити хеш у базі даних.
        Assert.True(result.RequiresRotation);
    }
}