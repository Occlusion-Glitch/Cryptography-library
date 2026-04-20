namespace OcclusionGlitch.Cryptography.Services.Interfaces;

/// <summary>
/// Defines the low-level engine for cryptographic hashing operations.
/// Designed for high-performance execution with minimal memory allocations.
/// </summary>
internal interface IHashEngine : IDisposable
{
    // === CLIENT METHODS === /* */
    /// <summary>
    /// Computes a cryptographic hash of the provided data combined with a salt.
    /// </summary>
    /// <param name="data">The input data buffer to be hashed.</param>
    /// <param name="salt">The secret salt or pepper buffer to strengthen the hash.</param>
    /// <param name="hash">The output buffer where the resulting hash will be written.</param>
    void ComputeHash(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> salt,
        Span<byte> hash);
    /* */
}