using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Internal.Snapshots;

/// <summary>
/// Represents a point-in-time snapshot of a hashing strategy's configuration.
/// Defines the algorithm, cost factors, and output constraints for hashing or index generation.
/// </summary>
internal readonly struct HashStrategySnapshot(
    HasherEngineType hashEngineType,
    HashAlgorithmName hashAlgorithm,
    int iterations,
    int hashSize,
    int saltSize,
    HashSettingsArgon2Snapshot? argon2 = null)
{
    // === PROPERTIES === /* */
    /// <summary>Gets the type of hashing engine (e.g., PBKDF2, Argon2id).</summary>
    public HasherEngineType HashEngineType { get; } = hashEngineType;
    /// <summary>Gets the underlying hash algorithm used by the engine (e.g., SHA256).</summary>
    public HashAlgorithmName HashAlgorithm { get; } = hashAlgorithm;
    /// <summary>Gets the number of computational iterations (or passes) to perform.</summary>
    public int Iterations { get; } = iterations;
    /// <summary>Gets the desired size of the resulting hash in bytes.</summary>
    public int HashSize { get; } = hashSize;
    /// <summary>Gets the required size of the salt or pepper buffer in bytes.</summary>
    public int SaltSize { get; } = saltSize;
    /// <summary> Gets the additional settings required for Argon2id operations, if applicable. </summary>
    public HashSettingsArgon2Snapshot? Argon2 { get; } = argon2;
    /* */
}