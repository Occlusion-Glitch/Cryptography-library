using OcclusionGlitch.Cryptography.Contracts.Snapshots;

namespace OcclusionGlitch.Cryptography.Contracts.Interfaces;

/// <summary>
/// Provides services for generating searchable "blind" indexes over encrypted data. 
/// Supports multiple index versions to allow for consistent searching during key rotation.
/// </summary>
public interface IBlindIndexService
{
    // === CLIENT METHODS === /* */
    /// <summary>
    /// Generates a complete set of searchable indices (target + allowed legacy versions) for the given plain text. 
    /// Use this method when performing a search query against the database to find records regardless of their rotation state.
    /// </summary>
    /// <param name="plainText">The raw data (e.g., Email, Phone) to index for searching.</param>
    /// <returns>A snapshot containing all valid indices for the current search context.</returns>
    BlindIndexResultSnapshot GenerateSearchIndices(string plainText);

    /// <summary>
    /// Generates a single blind index using the current target strategy and pepper version. 
    /// Use this method when inserting new records or performing a full rotation of existing ones.
    /// </summary>
    /// <param name="plainText">The raw data to index for storage.</param>
    /// <returns>A snapshot of the primary searchable index that meets current security standards.</returns>
    BlindIndexSnapshot GenerateTargetBlindIndex(string plainText);
    /* */
}