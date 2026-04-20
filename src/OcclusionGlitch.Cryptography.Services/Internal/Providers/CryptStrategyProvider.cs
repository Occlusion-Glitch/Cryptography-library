using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using System.Collections.Frozen;
using System.Security.Cryptography;
using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;

namespace OcclusionGlitch.Cryptography.Services.Internal.Providers;

/// <summary>
/// Provides a centralized registry of all cryptographic strategies supported by the system.
/// This provider is essential for resolving historical (legacy) strategies during decryption.
/// </summary>
internal static class CryptStrategyProvider
{
    // === PRIVATE PROPERTIES === /* */
    /// <summary>
    /// A high-performance, immutable cache of encryption strategies.
    /// Key: StrategyId (byte), Value: The immutable strategy snapshot.
    /// </summary>
    private static readonly FrozenDictionary<byte, CryptStrategySnapshot> _strategysCache =
        new Dictionary<byte, CryptStrategySnapshot>
        {
            // ID 1:
            // DerivedKey: SHA256, Key: 128-bit, Tag: 128-bit, Nonce: 96-bit (12-byte), Salt: 128-bit
            // -------------------------------------------------------------------------------------------------------------------
            // AES-128-GCM. Fastest option. Ideal for short-lived data (tokens) and JWE compatibility.
            { 1, new CryptStrategySnapshot(CipherEngineType.AesGcm, HashAlgorithmName.SHA256, (128 / 8), (128 / 8), (96 / 8), (128 / 8)) },

            // ID 2:
            // DerivedKey: SHA256, Key: 256-bit, Tag: 128-bit, Nonce: 96-bit (12-byte), Salt: 128-bit
            // -------------------------------------------------------------------------------------------------------------------
            // AES-256-GCM. Industry standard. Balances maximum security and speed. Default choice for DB storage.
            { 2, new CryptStrategySnapshot(CipherEngineType.AesGcm, HashAlgorithmName.SHA256, (256 / 8), (128 / 8), (96 / 8), (128 / 8)) },

            // ID 3:
            // DerivedKey: SHA512, Key: 256-bit, Tag: 128-bit, Nonce: 96-bit (12-byte), Salt: 128-bit
            // -------------------------------------------------------------------------------------------------------------------
            // AES-256-GCM + SHA512. "Top Secret" (Suite B) level. Stronger key derivation for strict compliance audits.
            { 3, new CryptStrategySnapshot(CipherEngineType.AesGcm, HashAlgorithmName.SHA512, (256 / 8), (128 / 8), (96 / 8), (128 / 8)) },

            // ... other versions AesGcm-based versions could be added here ...

            // ID 20:
            // DerivedKey: SHA512, Key: 256-bit, Tag: 128-bit, Nonce: 96-bit (12-byte), Salt: 128-bit
            // -------------------------------------------------------------------------------------------------------------------
            // ChaCha20-Poly1305. AES alternative. Best choice for mobile/IoT environments without AES-NI support.
            { 20, new CryptStrategySnapshot(CipherEngineType.ChaCha20Poly1305, HashAlgorithmName.SHA512, (256 / 8), (128 / 8), (96 / 8), (128 / 8)) },

            // ... other versions ChaCha20Poly1305-based versions could be added here ...

        }.ToFrozenDictionary();
    /* */

    // === CLIENT METHODS === /* */
    /// <summary>
    /// Retrieves the encryption strategy associated with the specified strategy identifier.
    /// </summary>
    /// <param name="strategyId">The unique ID of the strategy (parsed from the package header).</param>
    /// <returns>A snapshot containing the full configuration for the requested strategy.</returns>
    /// <exception cref="GlitchCryptException">Thrown when the strategy ID is not recognized.</exception>
    public static CryptStrategySnapshot GetStrategy(byte strategyId)
    {
        if (_strategysCache.TryGetValue(strategyId, out var snapshot))
            return snapshot;
        throw new GlitchCryptException($"The cryptography strategy ID '{strategyId}' is not supported or has been deprecated.");
    }
    /* */
}