namespace OcclusionGlitch.Cryptography.Services.Interfaces;

/// <summary>
/// Defines the contract for low-level cryptographic engines supporting Authenticated Encryption with Associated Data (AEAD).
/// Operates directly on memory spans to ensure high performance and zero-allocation processing.
/// </summary>
internal interface ICryptEngine : IDisposable
{
    // === PROPERTIES === /* */
    /// <summary>
    /// Encrypts the plaintext into the ciphertext buffer and generates an authentication tag.
    /// </summary>
    /// <param name="nonce">The unique initialization vector (nonce) for this operation.</param>
    /// <param name="plainText">The input buffer containing the data to be encrypted.</param>
    /// <param name="cipherText">The output buffer where the encrypted data will be written.</param>
    /// <param name="tag">The output buffer where the authentication tag will be stored.</param>
    void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plainText,
        Span<byte> cipherText,
        Span<byte> tag);

    /// <summary>
    /// Encrypts the plaintext into the ciphertext buffer while binding additional authenticated data (AAD).
    /// </summary>
    /// <param name="nonce">The unique initialization vector (nonce) for this operation.</param>
    /// <param name="plainText">The input buffer containing the data to be encrypted.</param>
    /// <param name="cipherText">The output buffer where the encrypted data will be written.</param>
    /// <param name="tag">The output buffer where the authentication tag will be stored.</param>
    /// <param name="associatedData">Extra data that must be authenticated but remains unencrypted.</param>
    void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plainText,
        Span<byte> cipherText,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData);

    /// <summary>
    /// Decrypts the ciphertext into the plaintext buffer and verifies integrity using the authentication tag.
    /// </summary>
    /// <param name="nonce">The nonce used during the encryption process.</param>
    /// <param name="cipherText">The input buffer containing the encrypted data.</param>
    /// <param name="plainText">The output buffer where the decrypted data will be written.</param>
    /// <param name="tag">The authentication tag to verify against the ciphertext.</param>
    /// <exception cref="System.Security.Cryptography.AuthenticationTagMismatchException">Thrown if the data has been tampered with or the tag is invalid.</exception>
    void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> cipherText,
        Span<byte> plainText,
        ReadOnlySpan<byte> tag);

    /// <summary>
    /// Decrypts the ciphertext and verifies the integrity of both the data and the associated authenticated data (AAD).
    /// </summary>
    /// <param name="nonce">The nonce used during the encryption process.</param>
    /// <param name="cipherText">The input buffer containing the encrypted data.</param>
    /// <param name="plainText">The output buffer where the decrypted data will be written.</param>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <param name="associatedData">The same additional data provided during encryption to ensure it hasn't been modified.</param>
    /// <exception cref="System.Security.Cryptography.AuthenticationTagMismatchException">Thrown if the data, tag, or AAD verification fails.</exception>
    void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> cipherText,
        Span<byte> plainText,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData);
    /* */
}