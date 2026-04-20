using OcclusionGlitch.Cryptography.Services.Engines.BlindIndexEngines;
using OcclusionGlitch.Cryptography.Services.Interfaces;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Factories;

/// <summary>
/// Factory for creating cryptographic engines used in blind index generation.
/// This factory abstracts the instantiation of specific HMAC implementations.
/// </summary>
internal static class BlindIndexEngineFactory
{
    // === FACTORY METHODS === /* */
    /// <summary>
    /// Creates a new instance of <see cref="IBlindIndexEngine"/> for the specified hash algorithm and pepper key.
    /// </summary>
    /// <param name="hashAlgorithm">The name of the hash algorithm to use (e.g., SHA256, SHA512).</param>
    /// <param name="pepper">The secret pepper key used for HMAC computation.</param>
    /// <returns>An implementation of <see cref="IBlindIndexEngine"/>.</returns>
    /// <exception cref="NotSupportedException">Thrown when the requested algorithm is not supported.</exception>
    public static IBlindIndexEngine Create(
        HashAlgorithmName hashAlgorithm,
        byte[] pepper) => hashAlgorithm.Name switch
        {
            "SHA256" => new HmacSha256Engine(pepper),
            "SHA512" => new HmacSha512Engine(pepper),
            _ => throw new NotSupportedException($"Hash algorithm {hashAlgorithm.Name} is not supported for blind index computation.")
        };
    /* */
}