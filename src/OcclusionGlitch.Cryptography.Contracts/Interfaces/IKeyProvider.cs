namespace OcclusionGlitch.Cryptography.Contracts.Interfaces;

/// <summary>
/// Defines a provider for retrieving cryptographic keys and pepper values based on their versioning.
/// Acts as the bridge between the key storage (Key Management) and the encryption/hashing engines.
/// </summary>
public interface IKeyProvider
{
    // === CLIENT METHODS === /* */
    /// <summary>
    /// Retrieves the encryption key associated with the specified version. 
    /// This key is used for symmetric encryption/decryption processes.
    /// </summary>
    /// <param name="keyVersion">The version of the key to retrieve (e.g., TargetCryptKeyVersion).</param>
    /// <returns>A byte array containing the raw encryption key.</returns>
    byte[] GetCryptKey(ushort keyVersion);

    /// <summary>
    /// Retrieves the pepper key (secret salt) associated with the specified version. 
    /// Used to strengthen hashes and generate consistent blind indexes.
    /// </summary>
    /// <param name="keyVersion">The version of the pepper to retrieve (e.g., TargetPepperKeyVersion).</param>
    /// <returns>A byte array containing the raw pepper value.</returns>
    byte[] GetPepperKey(ushort keyVersion);

    /// <summary>
    /// Asynchronously retrieves the encryption key associated with the specified version. 
    /// Ideal for implementations using external Key Management Systems (KMS).
    /// </summary>
    /// <param name="keyVersion">The version of the key to retrieve.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A task representing the asynchronous operation, containing the encryption key.</returns>
    Task<byte[]> GetCryptKeyAsync(ushort keyVersion, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously retrieves the pepper key associated with the specified version. 
    /// Ideal for implementations using external Key Management Systems (KMS).
    /// </summary>
    /// <param name="keyVersion">The version of the pepper to retrieve.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A task representing the asynchronous operation, containing the pepper value.</returns>
    Task<byte[]> GetPepperKeyAsync(ushort keyVersion, CancellationToken cancellationToken = default);
    /* */
}