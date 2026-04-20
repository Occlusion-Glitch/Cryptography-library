namespace OcclusionGlitch.Cryptography.Contracts.Snapshots;

/// <summary>Represents a generated blind index along with its metadata and status. Used for secure searching over encrypted data.</summary>
public readonly struct BlindIndexSnapshot(string fullBlindIndex, bool requiresRotation, string header)
{
    // === PROPERTIES === /* */
    /// <summary>Gets the complete blind index package. This string is used for exact-match searching in the database.</summary>
    public string FullBlindIndex { get; } = fullBlindIndex;
    /// <summary>Gets a value indicating whether this blind index was generated using outdated strategies or pepper versions and should be refreshed.</summary>
    public bool RequiresRotation { get; } = requiresRotation;
    /// <summary>Gets the header portion of the package. Typically contains the 1-byte StrategyId and 2-byte KeyVersion. (encoded in Base64 as 4 characters).</summary>
    public string Header { get; } = header;
    /* */
}