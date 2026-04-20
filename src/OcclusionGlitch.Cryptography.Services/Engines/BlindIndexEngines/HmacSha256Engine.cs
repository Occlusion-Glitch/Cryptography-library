using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Services.Interfaces;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Engines.BlindIndexEngines;

/// <summary>
/// A high-performance blind index engine that utilizes the HMAC-SHA256 algorithm.
/// This is the industry-standard choice for generating secure, deterministic search indices.
/// </summary>
/// <param name="pepper">The secret pepper key used for HMAC computation.</param>
internal class HmacSha256Engine(byte[] pepper) : IBlindIndexEngine
{
    // === PROPERTIES === /* */
    public int HashSize => 32; // HMAC-SHA256 produces a 32-byte (256-bit) hash
    // === PROPERTIES (PRIVATE) ===
    private readonly HMACSHA256 _hmac = new HMACSHA256(pepper);
    /* */

    // === CLIENT METHODS === /* */
    /// <summary>
    /// Computes the HMAC-SHA256 hash of the specified input data and writes the result to the provided destination buffer.
    /// </summary>
    /// <param name="data">The input data to hash.</param>
    /// <param name="destination">The buffer that receives the computed HMAC-SHA256 hash. Must be at least 32 bytes in length.</param>
    /// <exception cref="GlitchCryptException">Thrown if the hash computation fails or if the destination buffer is too small.</exception>
    public void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        // We use TryComputeHash to write directly into the provided span.
        // This avoids creating temporary byte arrays and reduces pressure on the Garbage Collector.
        if (!_hmac.TryComputeHash(data, destination, out _))
            throw new GlitchCryptException("Failed to compute HMAC-SHA256. Ensure the destination buffer is at least 32 bytes.");
    }

    /// <summary>
    /// Releases all resources used by the HMAC-SHA256 engine.
    /// </summary>
    public void Dispose() => _hmac.Dispose();
    /* */
}