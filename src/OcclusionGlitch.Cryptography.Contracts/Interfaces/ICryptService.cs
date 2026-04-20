using OcclusionGlitch.Cryptography.Contracts.Snapshots;

namespace OcclusionGlitch.Cryptography.Contracts.Interfaces;

/// <summary>
/// Provides high-level encryption and decryption services using the system's target strategies. 
/// Handles the lifecycle of encrypted data, including support for legacy decryption and rotation.
/// </summary>
public interface ICryptService
{
    // === CLIENT METHODS === /* */
    /// <summary>
    /// Encrypts the specified plain text using the current target encryption strategy and target key version. 
    /// This method is intended for all new encryption operations to ensure data meets current security standards.
    /// </summary>
    /// <param name="plainText">The sensitive data to be encrypted.</param>
    /// <param name="associatedData">Optional additional data to be authenticated but not encrypted.</param>
    /// <returns>A snapshot containing the full encrypted package (header + cipher) and its metadata.</returns>
    CryptResultSnapshot EncryptTarget(string plainText, string? associatedData = null);

    /// <summary>
    /// Decrypts the specified cipher text package. 
    /// The service automatically resolves the required strategy and key version from the package's header.
    /// </summary>
    /// <param name="cipherText">The full encrypted package (including header and cryptographic payload).</param>
    /// <param name="associatedData">Optional additional data to be authenticated but not encrypted.</param>
    /// <returns>A result snapshot containing the decrypted plain text and rotation recommendations.</returns>
    DecryptResultSnapshot Decrypt(string cipherText, string? associatedData = null);
    /* */
}