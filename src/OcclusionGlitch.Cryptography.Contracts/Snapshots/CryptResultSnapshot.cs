namespace OcclusionGlitch.Cryptography.Contracts.Snapshots;

/// <summary>Represents the result of an encryption operation. Contains the final encrypted package and the metadata header used during its creation.</summary>
public readonly struct CryptResultSnapshot(string fullCipher, string header)
{
    // === PROPERTIES === /* */
    /// <summary>Gets the complete cryptographic package. This string includes the header, initialization vector, and the encrypted payload, formatted for storage in the database.</summary>
    public string FullCipher { get; } = fullCipher;
    /// <summary>Gets the header portion of the package. Typically contains the 1-byte StrategyId and 2-byte KeyVersion. (encoded in Base64 as 4 characters).</summary>
    public string Header { get; } = header;
    /* */
}