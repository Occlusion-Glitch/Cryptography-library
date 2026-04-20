using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;
using System.Collections.Frozen;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Internal.Providers;

/// <summary>
/// Provides a centralized registry of all hashing strategies supported by the system.
/// Used for password hashing, data integrity checks.
/// </summary>
internal static class HashStrategyProvider
{
    // === PRIVATE PROPERTIES === /* */
    /// <summary>
    /// A high-performance, immutable cache of hashing strategies.
    /// Key: StrategyId (byte), Value: The immutable strategy snapshot.
    /// </summary>
    private static readonly FrozenDictionary<byte, HashStrategySnapshot> _strategysCache =
        new Dictionary<byte, HashStrategySnapshot>
        {
            // ID 1: PBKDF2 with SHA-256
            // High iterations (600k) as per OWASP recommendations for password hashing.
            // Hash: 256-bit, Salt: 128-bit
            { 1, new HashStrategySnapshot(HasherEngineType.PBKDF2, HashAlgorithmName.SHA256, 600000, (256 / 8), (128 / 8)) },

            // ... other versions PBKDF2-based versions could be added here ...

            // ID 20: Argon2id (Memory-Hard)
            // 3 iterations, 32 MiB memory, parallelism 1. Superior protection against GPU cracking.
            // Hash: 256-bit, Salt: 128-bit
            { 20, new HashStrategySnapshot(HasherEngineType.Argon2id, HashAlgorithmName.SHA256, 3, (256 / 8), (128 / 8), new HashSettingsArgon2Snapshot(memorySizeKb: 32768, parallelism: 1, iterations: 3)) }

            // ... other versions Argon2id-based versions could be added here ...

        }.ToFrozenDictionary();
    /* */

    // === CLIENT METHODS === /* */
    /// <summary>
    /// Retrieves the hashing strategy associated with the specified strategy identifier.
    /// </summary>
    /// <param name="strategyId">The unique ID of the strategy (parsed from the package header).</param>
    /// <returns>A snapshot containing the full configuration for the requested strategy.</returns>
    /// <exception cref="GlitchCryptException">Thrown when the strategy ID is not recognized.</exception>
    public static HashStrategySnapshot GetStrategy(byte strategyId)
    {
        if (_strategysCache.TryGetValue(strategyId, out var snapshot))
            return snapshot;
        throw new GlitchCryptException($"The hashing strategy ID '{strategyId}' is not supported or has been deprecated.");
    }
    /* */
}