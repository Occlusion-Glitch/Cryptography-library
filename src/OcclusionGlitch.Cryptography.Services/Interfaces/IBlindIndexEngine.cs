namespace OcclusionGlitch.Cryptography.Services.Interfaces;

/// <summary>
/// Defines the contract for cryptographic engines used to compute blind indices.
/// Implementations provide high-performance HMAC computation using memory-efficient buffers.
/// </summary>
internal interface IBlindIndexEngine : IDisposable
{
    // === CLIENT METHODS === /* */
    /// <summary>Gets the full output size (in bytes) of the hashing algorithm used by the engine.</summary>
    int HashSize { get; }

    /// <summary>
    /// Computes the HMAC hash for the given data and writes the result to the destination buffer.
    /// </summary>
    /// <param name="data">The input data to be hashed.</param>
    /// <param name="destination">The span where the full hash result will be written.</param>
    void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination);
    /* */
}