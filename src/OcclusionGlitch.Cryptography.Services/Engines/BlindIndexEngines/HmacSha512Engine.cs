using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Services.Interfaces;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Engines.BlindIndexEngines;

/// <summary>
/// A high-performance blind index engine that utilizes the HMAC-SHA512 algorithm.
/// Suitable for environments requiring maximum hash entropy and collision resistance.
/// </summary>
/// <param name="pepper">The secret pepper key used for HMAC computation.</param>
internal class HmacSha512Engine(byte[] pepper) : IBlindIndexEngine
{
    // === PROPERTIES === /* */
    public int HashSize => 64; // HMAC-SHA512 produces a 64-byte (512-bit) hash
    // === PROPERTIES (PRIVATE) ===
    private readonly HMACSHA512 _hmac = new HMACSHA512(pepper);
    /* */

    // === CLIENT METHODS === /* */
    /// <summary>
    /// Computes the HMAC-SHA512 hash of the specified input data and writes the result to the provided destination
    /// buffer.
    /// </summary>
    /// <param name="data">The input data to hash.</param>
    /// <param name="destination">The buffer that receives the computed HMAC-SHA512 hash. Must be at least 64 bytes in length.</param>
    /// <exception cref="GlitchCryptException">Thrown if the hash computation fails or if the destination buffer is too small.</exception>
    public void ComputeHash(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        // We use TryComputeHash to write directly into the provided span.
        // This avoids creating temporary byte arrays and reduces Pressure on the Garbage Collector.
        if (!_hmac.TryComputeHash(data, destination, out _))
            throw new GlitchCryptException("Failed to compute HMAC-SHA512. Ensure the destination buffer is at least 64 bytes.");
    }

    /// <summary>
    /// Releases all resources used by the current instance of the class.
    /// </summary>
    public void Dispose() => _hmac.Dispose();
    /* */
}