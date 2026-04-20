using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;
using System.Collections.Frozen;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Internal.Providers;

/// <summary>
/// Provides a centralized registry of all blind index strategies supported by the system.
/// This provider is essential for resolving historical strategies and maintaining search consistency.
/// </summary>
internal static class BlindIndexStrategyProvider
{
    // === PRIVATE PROPERTIES === /* */
    /// <summary>
    /// A high-performance, immutable cache of blind index strategies.
    /// Key: StrategyId (byte), Value: The immutable strategy snapshot.
    /// </summary>
    private static readonly FrozenDictionary<byte, BlindIndexStrategySnapshot> _strategysCache =
        new Dictionary<byte, BlindIndexStrategySnapshot>
        {
            // ID 1:
            // Algorithm: HMAC-SHA256, Output: 256-bit (32-byte)
            // -------------------------------------------------------------------------------------------------------------------
            // Full-length HMAC-SHA256. Provides maximum collision resistance for large-scale datasets.
            { 1, new BlindIndexStrategySnapshot(HashAlgorithmName.SHA256, (256 / 8)) },

            // ID 2:
            // Algorithm: HMAC-SHA256, Output: 128-bit (16-byte)
            // -------------------------------------------------------------------------------------------------------------------
            // Truncated 128-bit HMAC-SHA256. Optimized for database storage while maintaining secure lookup entropy.
            { 2, new BlindIndexStrategySnapshot(HashAlgorithmName.SHA256, (128 / 8)) },

            // ... other HMAC-based versions could be added here ...

        }.ToFrozenDictionary();
    /* */

    // === CLIENT METHODS === /* */
    /// <summary>
    /// Retrieves the blind index strategy associated with the specified strategy identifier.
    /// </summary>
    /// <param name="strategyId">The unique ID of the strategy (parsed from the stored index header).</param>
    /// <returns>A snapshot containing the full configuration for the requested strategy.</returns>
    /// <exception cref="GlitchCryptException">Thrown when the strategy ID is not recognized.</exception>
    public static BlindIndexStrategySnapshot GetStrategy(byte strategyId)
    {
        if (_strategysCache.TryGetValue(strategyId, out var snapshot))
            return snapshot;
        throw new GlitchCryptException($"The hash strategy with id {strategyId} is not supported.");
    }
    /* */
}