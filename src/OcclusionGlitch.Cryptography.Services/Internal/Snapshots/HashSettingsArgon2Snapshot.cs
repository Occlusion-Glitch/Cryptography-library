namespace OcclusionGlitch.Cryptography.Services.Internal.Snapshots;

/// <summary>Represents a snapshot of the Argon2id-specific configuration settings, such as memory usage and degree of parallelism.</summary>
internal readonly struct HashSettingsArgon2Snapshot(int memorySizeKb, int parallelism, int iterations)
{
    // === PROPERTIES === /* */
    /// <summary>Gets the amount of memory to be used by the Argon2id algorithm, in kilobytes. Higher values increase resistance against specialized hardware attacks (ASICs).</summary>
    public int MemorySizeKb { get; } = memorySizeKb;
    /// <summary>Gets the number of threads to be used by the Argon2id algorithm. This defines the computational cost and resource utilization.</summary>
    public int Parallelism { get; } = parallelism;
    /// <summary>Gets the number of iterations (time cost). Defines the number of passes over the memory. Increasing this value makes hashing slower and more resistant to attacks but increases processing time.</summary>
    public int Iterations { get; init; } = iterations;
    /* */
}