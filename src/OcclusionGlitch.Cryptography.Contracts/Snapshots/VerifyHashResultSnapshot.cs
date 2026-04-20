namespace OcclusionGlitch.Cryptography.Contracts.Snapshots;

/// <summary>Represents the result of a hash verification operation, including security status and maintenance recommendations.</summary>
public readonly struct VerifyHashResultSnapshot(bool isMatch, bool requiresRotation, string header)
{
    // === PROPERTIES === /* */
    /// <summary>Gets a value indicating whether the provided plain text matches the hash.</summary>
    public bool IsMatch { get; } = isMatch;
    /// <summary>Gets a value indicating whether the hash was produced using outdated strategies or keys and should be updated (rotated) to the current targets.</summary>
    public bool RequiresRotation { get; } = requiresRotation;
    /// <summary>Gets the header portion of the package. Typically contains the 1-byte StrategyId and 2-byte KeyVersion. (encoded in Base64 as 4 characters).</summary>
    public string Header { get; } = header;
    /* */
}