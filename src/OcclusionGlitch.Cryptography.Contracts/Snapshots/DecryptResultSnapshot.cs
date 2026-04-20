namespace OcclusionGlitch.Cryptography.Contracts.Snapshots;

/// <summary>Represents the result of a decryption operation, including the recovered plain text and information about the security state of the source cipher.</summary>
public readonly struct DecryptResultSnapshot(string plainText, bool requiresRotation, string header)
{
    // === PROPERTIES === /* */
    /// <summary>Gets the decrypted plain text string.</summary>
    public string PlainText { get; } = plainText;
    /// <summary>Gets a value indicating whether the data was encrypted with an outdated strategy or key version. If true, the data should be re-encrypted using the current "Target" settings.</summary>
    public bool RequiresRotation { get; } = requiresRotation;
    /// <summary>Gets the header portion of the package. Typically contains the 1-byte StrategyId and 2-byte KeyVersion. (encoded in Base64 as 4 characters).</summary>
    public string Header { get; } = header;
    /* */
}