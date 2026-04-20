using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Internal.Snapshots;

/// <summary>
/// Represents a point-in-time snapshot of a cryptographic strategy's configuration.
/// This immutable structure defines the specific algorithms and buffer sizes used for encryption.
/// </summary>
internal readonly struct CryptStrategySnapshot(
    CipherEngineType engineType,
    HashAlgorithmName hashAlgorithm,
    int keySize,
    int tagSize,
    int nonceSize,
    int saltSize)
{
    // === PROPERTIES === /* */
    /// <summary>Gets the type of encryption engine (e.g., AesGcm, ChaCha20Poly1305).</summary>
    public CipherEngineType EngineType { get; init; } = engineType;
    /// <summary>Gets the hash algorithm used for key derivation (e.g., SHA256, SHA512).</summary>
    public HashAlgorithmName KdfHashAlgorithm { get; init; } = hashAlgorithm;
    /// <summary>Gets the size of the symmetric key in bytes (typically 32 for AES-256).</summary>
    public int KeySize { get; init; } = keySize;
    /// <summary>Gets the size of the authentication tag in bytes (typically 16).</summary>
    public int TagSize { get; init; } = tagSize;
    /// <summary>Gets the size of the initialization vector (nonce) in bytes (typically 12).</summary>
    public int NonceSize { get; init; } = nonceSize;
    /// <summary>Gets the size of the salt used during key derivation in bytes.</summary>
    public int SaltSize { get; init; } = saltSize;
    /* */
}