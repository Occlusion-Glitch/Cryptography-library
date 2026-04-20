namespace OcclusionGlitch.Cryptography.Contracts.Snapshots;

/// <summary>Represents a snapshot of a hashing operation result, containing both the stored value and the metadata used to produce it.</summary>
public readonly struct HashResultSnapshot(string fullHash, string header)
{
    // === PROPERTIES === /* */
    /// <summary>Gets the full cryptographic package. This string includes the header prefix and the hash digest, formatted specifically for storage in the database.</summary>
    public string FullHash { get; } = fullHash;
    /// <summary>Gets the header portion of the package. Typically contains the 1-byte StrategyId and 2-byte KeyVersion. (encoded in Base64 as 4 characters).</summary>
    public string Header { get; } = header;
    /* */
}