namespace OcclusionGlitch.Cryptography.Contracts.Options;

public class GlitchCryptOptions
{
    // === PROPERTIES === /* */
    // === PROPERTIES (STRATEGY) ===
    /// <summary> Gets or sets the target strategy ID for encryption and decryption. This represents the current standard protocol; data using other IDs may be flagged for rotation. </summary>
    public byte TargetCryptStrategyId { get; set; } = 20;
    /// <summary> Gets or sets the target strategy ID for cryptographic hashing. Determines the active algorithm suite for password or data hashing. </summary>
    public byte TargetHashStrategyId { get; set; } = 20;
    /// <summary> Gets or sets the target strategy ID for blind index generation. Ensures consistent searchability across encrypted datasets using the active protocol. </summary>
    public byte TargetBlindIndexStrategyId { get; set; } = 20;

    // === PROPERTIES (KEY MANAGEMENT) ===
    /* * Key versions define which specific cryptographic keys from the storage are currently active.
     * The "Target" versions are used for all new write operations. Any data found with a different 
     * version ID is considered stale and should be rotated to these target versions.
     */
    /// <summary> Gets or sets the active key version for encryption and decryption (1-65535). Used as the primary key for protecting sensitive data. </summary>
    public ushort TargetCryptKeyVersion { get; set; } = 1;
    /// <summary> Gets or sets the active pepper key version used in hashing and blind indexing. This version is used for all newly generated hashes. </summary>
    public ushort TargetPepperKeyVersion { get; set; } = 1;
    /// <summary>Gets or sets the collection of legacy pepper key versions still supported for verification. Allows the system to validate existing blind indexes created with previous keys without immediate re-indexing.</summary>
    public ushort[] LegacyPepperKeyVersions { get; set; } = Array.Empty<ushort>();

    // === PROPERTIES (OTHER) ===
    /// <summary> Optional configuration for the Argon2 hashing algorithm. If null, default system parameters or alternative providers will be used. </summary>
    public Argon2Options? Argon2Options { get; set; } = null;
    /* */
}