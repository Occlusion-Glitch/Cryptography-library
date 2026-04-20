using System.Collections.Immutable;

namespace OcclusionGlitch.Cryptography.Contracts.Snapshots;

/// <summary>Represents the aggregated result of blind index generation, containing all compatible indices for searching and identifying rotation needs.</summary>
public readonly struct BlindIndexResultSnapshot
{
    // === PROPERTIES === /* */
    /// <summary>Gets the immutable collection of all generated blind indices. Includes the target index and any legacy versions required for backward compatibility.</summary>
    public ImmutableArray<BlindIndexSnapshot> AllFullIndices { get; init; }
    /// <summary>Gets the pre-calculated primary blind index that matches the current system "Target" standards. This value is "frozen" during construction for performance.</summary>
    public BlindIndexSnapshot TargetBlindIndex { get; init; }
    /// <summary>Gets a value indicating whether any of the indices are outdated or if the system standards have moved beyond the primary index provided.</summary>
    public bool RequiresRotation { get; init; }
    /* */

    // === CONSTRUCTOR === /* */
    public BlindIndexResultSnapshot(ImmutableArray<BlindIndexSnapshot> allFullIndices, bool requiresRotation)
    {
        AllFullIndices = allFullIndices;
        RequiresRotation = requiresRotation;

        // Calculate the TargetBlindIndex based on the provided indices
        TargetBlindIndex = AllFullIndices.IsDefaultOrEmpty ? default : AllFullIndices.FirstOrDefault(bi => !bi.RequiresRotation);
    }
    /* */
}