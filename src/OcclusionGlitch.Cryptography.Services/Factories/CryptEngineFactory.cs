using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Services.Interfaces;
using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using OcclusionGlitch.Cryptography.Services.Engines.CryptEngines;

namespace OcclusionGlitch.Cryptography.Services.Factories;

/// <summary>
/// A factory for creating instances of cryptographic engines based on the specified engine type.
/// </summary>
internal static class CryptEngineFactory
{
    // === FACTORY METHODS === /* */
    /// <summary>
    /// Creates an instance of <see cref="ICryptEngine"/> for the specified algorithm.
    /// </summary>
    /// <param name="engineType">The type of cryptographic engine to create (e.g., AesGcm, ChaCha20Poly1305).</param>
    /// <param name="derivedKey">The symmetric key material used for encryption/decryption.</param>
    /// <param name="tagSize">The size, in bytes, of the authentication tag (used by engines like AES-GCM).</param>
    /// <returns>An implementation of <see cref="ICryptEngine"/>.</returns>
    /// <exception cref="GlitchCryptException">Thrown when an unsupported engine type is requested.</exception>
    public static ICryptEngine Create(
        CipherEngineType engineType,
        ReadOnlySpan<byte> derivedKey,
        int tagSize) => engineType switch
        {
            CipherEngineType.AesGcm => new AesGcmEngine(derivedKey, tagSize),
            CipherEngineType.ChaCha20Poly1305 => new ChaCha20Poly1305Engine(derivedKey),
            _ => throw new GlitchCryptException($"The cipher engine type '{engineType}' is not supported by the system.")
        };
    /* */
}