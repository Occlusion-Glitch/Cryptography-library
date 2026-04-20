using OcclusionGlitch.Cryptography.Services.Interfaces;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Engines.HashEngines;

/// <summary>
/// Provides a PBKDF2 (Password-Based Key Derivation Function 2) implementation 
/// of the hash engine, primarily used for password hashing and key derivation.
/// </summary>
/// <param name="hashAlgorithm">The hash algorithm to use (e.g., SHA256, SHA512).</param>
/// <param name="iterations">The number of iterations to perform, which increases the computational cost of hashing.</param>
internal sealed class Pbkdf2Engine(HashAlgorithmName hashAlgorithm, int iterations) : IHashEngine
{
    // === CLIENT METHODS === /* */
    /// <summary>
    /// Computes a PBKDF2 hash using the configured iterations and hash algorithm.
    /// </summary>
    /// <param name="data">The input password or data buffer.</param>
    /// <param name="salt">The salt or pepper buffer used for derivation.</param>
    /// <param name="hash">The output buffer where the derived key/hash will be written.</param>
    public void ComputeHash(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> salt,
        Span<byte> hash)
        => Rfc2898DeriveBytes.Pbkdf2(data, salt, hash, iterations, hashAlgorithm);

    /// <summary>
    /// Disposes of any resources. For PBKDF2 static implementation, this is a no-op.
    /// </summary>
    public void Dispose()
    {
        // Static PBKDF2 doesn't hold unmanaged resources, 
        // but we implement IDisposable to satisfy the IHashEngine contract.
    }
    /* */
}