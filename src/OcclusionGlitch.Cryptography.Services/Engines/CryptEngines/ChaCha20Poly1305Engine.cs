using OcclusionGlitch.Cryptography.Services.Interfaces;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Engines.CryptEngines;

/// <summary>
/// Provides a high-performance implementation of the ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) algorithm.
/// </summary>
/// <remarks>
/// This engine is optimized for software-based implementations and is often faster than AES-GCM on hardware without 
/// specialized AES instructions. Note: This class is not thread-safe and follows the IETF RFC 8439 standard.
/// </remarks>
internal sealed class ChaCha20Poly1305Engine(ReadOnlySpan<byte> derivedKey) : ICryptEngine
{
    // === PRIVATE PROPERTIES === /* */
    private readonly ChaCha20Poly1305 _chacha = new(derivedKey);
    /* */

    // === CLIENT METHODS === /* */
    /// <summary>
    /// Encrypts the plaintext into the ciphertext buffer and generates an authentication tag.
    /// </summary>
    /// <param name="nonce">The 12-byte (96-bit) unique initialization vector for this operation.</param>
    /// <param name="plainText">The input buffer containing the data to encrypt.</param>
    /// <param name="cipherText">The output buffer where the encrypted data will be written.</param>
    /// <param name="tag">The output buffer where the generated 16-byte authentication tag will be written.</param>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plainText,
        Span<byte> cipherText,
        Span<byte> tag) => _chacha.Encrypt(nonce, plainText, cipherText, tag);

    /// <summary>
    /// Encrypts the plaintext with additional authenticated data (AAD) and generates an authentication tag.
    /// </summary>
    /// <param name="nonce">The 12-byte (96-bit) unique initialization vector for this operation.</param>
    /// <param name="plainText">The input buffer containing the data to encrypt.</param>
    /// <param name="cipherText">The output buffer where the encrypted data will be written.</param>
    /// <param name="tag">The output buffer where the generated 16-byte authentication tag will be written.</param>
    /// <param name="associatedData">Extra data to authenticate. This data remains unencrypted but is protected against tampering.</param>
    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plainText,
        Span<byte> cipherText,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData) => _chacha.Encrypt(nonce, plainText, cipherText, tag, associatedData);

    /// <summary>
    /// Decrypts the ciphertext into the plaintext buffer and verifies integrity using the authentication tag.
    /// </summary>
    /// <param name="nonce">The nonce that was used during the encryption process.</param>
    /// <param name="cipherText">The input buffer containing the encrypted data.</param>
    /// <param name="plainText">The output buffer where the decrypted data will be written.</param>
    /// <param name="tag">The 16-byte authentication tag to verify against the ciphertext.</param>
    /// <exception cref="AuthenticationTagMismatchException">Thrown if the tag verification fails.</exception>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> cipherText,
        Span<byte> plainText,
        ReadOnlySpan<byte> tag) => _chacha.Decrypt(nonce, cipherText, tag, plainText);

    /// <summary>
    /// Decrypts the ciphertext with additional authenticated data (AAD) and verifies integrity.
    /// </summary>
    /// <param name="nonce">The nonce that was used during the encryption process.</param>
    /// <param name="cipherText">The input buffer containing the encrypted data.</param>
    /// <param name="plainText">The output buffer where the decrypted data will be written.</param>
    /// <param name="tag">The 16-byte authentication tag to verify.</param>
    /// <param name="associatedData">The same AAD that was provided during encryption to ensure integrity.</param>
    /// <exception cref="AuthenticationTagMismatchException">Thrown if the tag or AAD verification fails.</exception>
    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> cipherText,
        Span<byte> plainText,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData) => _chacha.Decrypt(nonce, cipherText, tag, plainText, associatedData);
    /* */

    /// <summary>
    /// Disposes of the underlying ChaCha20-Poly1305 resources.
    /// </summary>
    public void Dispose() => _chacha.Dispose();
    /* */
}