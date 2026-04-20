namespace OcclusionGlitch.Cryptography.Contracts.Options;

public class Argon2Options
{
    // === PROPERTIES === /* */
    /// <summary>Gets the memory cost in Kibibytes (KiB). Defines the amount of RAM the algorithm will use. Higher values increase resistance to specialized hardware attacks (ASIC/GPU) but require more system memory. Default is 32768 KiB (32 MiB).</summary>
    public int MemorySizeKiB { get; init; } = (32 * 1024);
    /// <summary>Gets the degree of parallelism. Specifies the number of threads to be used by the algorithm. This should ideally be tuned to the number of available CPU cores.</summary>
    public int DegreeOfParallelism { get; init; } = 1;
    /// <summary>Gets the number of iterations (time cost). Defines the number of passes over the memory. Increasing this value makes hashing slower and more resistant to attacks but increases processing time.</summary>
    public int Iterations { get; init; } = 3;
    /* */
}