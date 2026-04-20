using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Internal.Snapshots;

/// <summary>
/// Represents a point-in-time configuration for a blind index generation strategy.
/// This snapshot defines the cryptographic primitives and output constraints.
/// </summary>
internal readonly struct BlindIndexStrategySnapshot(HashAlgorithmName hashAlgorithm,int outputSize)
{
    // === PROPERTIES === /* */
    /// <summary> Gets the hashing algorithm name used by the HMAC engine.</summary>
    public HashAlgorithmName HashAlgorithm { get; } = hashAlgorithm;
    /// <summary>Gets the desired length of the resulting blind index in bytes. If this is smaller than the engine's full output, the hash will be truncated.</summary>
    public int OutputSize { get; } = outputSize;
    /* */
}