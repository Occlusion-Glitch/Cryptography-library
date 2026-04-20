namespace OcclusionGlitch.Cryptography.Services.Internal.Enums;

/// <summary>
/// Specifies the type of cryptographic engine used for symmetric encryption and decryption.
/// </summary>
internal enum CipherEngineType : byte
{
    /// <summary>
    /// AES (Advanced Encryption Standard) in Galois/Counter Mode.
    /// Provides high performance with hardware acceleration (AES-NI) and built-in authentication.
    /// </summary>
    AesGcm = 1,

    /// <summary>
    /// ChaCha20 stream cipher combined with Poly1305 authenticator.
    /// Excellent software-based performance, especially on systems without AES hardware acceleration.
    /// </summary>
    ChaCha20Poly1305 = 2
}