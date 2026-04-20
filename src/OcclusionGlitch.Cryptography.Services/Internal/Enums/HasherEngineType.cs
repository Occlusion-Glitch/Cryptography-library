namespace OcclusionGlitch.Cryptography.Services.Internal.Enums;

/// <summary>
/// Specifies the type of hashing engine used for protecting data or generating blind indices.
/// </summary>
internal enum HasherEngineType : byte
{
    /// <summary>
    /// Password-Based Key Derivation Function 2.
    /// A reliable, standard-compliant algorithm. Good for search indices and legacy password support.
    /// </summary>
    PBKDF2 = 1,

    /// <summary>
    /// Argon2id (Memory-Hard Hashing).
    /// The state-of-the-art hashing algorithm, resistant to GPU/ASIC attacks. 
    /// Recommended for modern password protection and sensitive data hashing.
    /// </summary>
    Argon2id = 2
}