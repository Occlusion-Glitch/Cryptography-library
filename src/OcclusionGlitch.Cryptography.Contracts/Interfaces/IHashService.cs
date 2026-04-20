using OcclusionGlitch.Cryptography.Contracts.Snapshots;

namespace OcclusionGlitch.Cryptography.Contracts.Interfaces;

/// <summary>
/// Provides methods for secure data hashing and verification, 
/// enforcing the "Target" security standards defined in the system options.
/// </summary>
public interface IHashService
{
    // === CLIENT METHODS === /* */
    /// <summary>
    /// Generates a hash package using the current target hashing strategy and the target pepper version. 
    /// This is the primary method for protecting new passwords or sensitive data.
    /// </summary>
    /// <param name="plainText">The raw data to be hashed.</param>
    /// <returns>A snapshot containing the resulting hash package and the specific strategy/key versions used.</returns>
    HashResultSnapshot GenerateTargetHash(string plainText);

    /// <summary>
    /// Verifies a plain text string against a hashed package. 
    /// The service automatically resolves the strategy and pepper version from the package's header, 
    /// allowing for seamless verification of legacy hashes.
    /// </summary>
    /// <param name="plainText">The raw data to verify.</param>
    /// <param name="hashedPackage">The hash package (including header) stored in the database.</param>
    /// <returns>A result indicating if the match was successful and if the hash should be updated to a newer target.</returns>
    VerifyHashResultSnapshot VerifyHash(string plainText, string hashedPackage);
    /* */
}