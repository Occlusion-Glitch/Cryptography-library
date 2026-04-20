using OcclusionGlitch.Cryptography.Services.Interfaces;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Engines.CryptEngines;

/// <summary>
/// Provides an implementation of the AES-GCM (Galois/Counter Mode) cryptographic engine 
/// for authenticated encryption and decryption operations.
/// </summary>
/// <remarks>
/// This engine provides Authenticated Encryption with Associated Data (AEAD) support. 
/// AES-GCM is hardware-accelerated on most modern CPUs. The engine is not thread-safe; 
/// concurrent use must be externally synchronized.
/// </remarks>
internal class AesGcmEngine(ReadOnlySpan<byte> derivedKey, int tagSize) : ICryptEngine
{
    // === PRIVATE PROPERTIES === /* */
    private readonly AesGcm _aesGcm = new AesGcm(derivedKey, tagSize);
    /* */

    // === CLIENT METHODS === /* */
    /// <summary>
    /// Encrypts the plaintext into the ciphertext buffer and generates an authentication tag.
    /// </summary>
    /// <param name="nonce">The 12-byte (96-bit) unique initialization vector for this operation.</param>
    /// <param name="plainText">The input buffer containing the data to encrypt.</param>
    /// <param name="cipherText">The output buffer where the encrypted data will be written.</param>
    /// <param name="tag">The output buffer where the generated authentication tag will be written.</param>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plainText,
        Span<byte> cipherText,
        Span<byte> tag) => _aesGcm.Encrypt(nonce, plainText, cipherText, tag);

    /// <summary>
    /// Encrypts the plaintext with additional authenticated data (AAD) and generates an authentication tag.
    /// </summary>
    /// <param name="nonce">The 12-byte (96-bit) unique initialization vector for this operation.</param>
    /// <param name="plainText">The input buffer containing the data to encrypt.</param>
    /// <param name="cipherText">The output buffer where the encrypted data will be written.</param>
    /// <param name="tag">The output buffer where the generated authentication tag will be written.</param>
    /// <param name="associatedData">Extra data to authenticate. This data remains unencrypted but is protected against tampering.</param>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plainText,
        Span<byte> cipherText,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData) => _aesGcm.Encrypt(nonce, plainText, cipherText, tag, associatedData);

    /// <summary>
    /// Decrypts the ciphertext into the plaintext buffer and verifies integrity using the authentication tag.
    /// </summary>
    /// <param name="nonce">The nonce that was used during the encryption process.</param>
    /// <param name="cipherText">The input buffer containing the encrypted data.</param>
    /// <param name="plainText">The output buffer where the decrypted data will be written.</param>
    /// <param name="tag">The authentication tag to verify against the ciphertext.</param>
    /// <exception cref="System.Security.Cryptography.AuthenticationTagMismatchException">Thrown if the tag verification fails.</exception>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> cipherText,
        Span<byte> plainText,
        ReadOnlySpan<byte> tag) => _aesGcm.Decrypt(nonce, cipherText, tag, plainText);

    /// <summary>
    /// Decrypts the ciphertext with additional authenticated data (AAD) and verifies integrity.
    /// </summary>
    /// <param name="nonce">The nonce that was used during the encryption process.</param>
    /// <param name="cipherText">The input buffer containing the encrypted data.</param>
    /// <param name="plainText">The output buffer where the decrypted data will be written.</param>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <param name="associatedData">The same AAD that was provided during encryption to ensure integrity.</param>
    /// <exception cref="System.Security.Cryptography.AuthenticationTagMismatchException">Thrown if the tag or AAD verification fails.</exception>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> cipherText,
        Span<byte> plainText,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData) => _aesGcm.Decrypt(nonce, cipherText, tag, plainText, associatedData);
    /* */

    /// <summary>
    /// Releases all resources used by the AES-GCM engine.
    /// </summary>
    public void Dispose() => _aesGcm.Dispose();
    /* */
}