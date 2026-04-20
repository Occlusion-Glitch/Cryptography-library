using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Services.Interfaces;
using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;
using OcclusionGlitch.Cryptography.Services.Engines.HashEngines;

namespace OcclusionGlitch.Cryptography.Services.Factories;

/// <summary>
/// A factory for creating instances of hashing engines based on the specified engine type and settings.
/// </summary>
internal static class HashEngineFactory
{
    // === FACTORY METHODS === /* */
    /// <summary>
    /// Creates an instance of <see cref="IHashEngine"/> for the specified hashing algorithm.
    /// </summary>
    /// <param name="engineType">The type of hashing engine to create (e.g., PBKDF2, Argon2id).</param>
    /// <param name="settings">The general hashing settings (iterations, algorithm name).</param>
    /// <param name="argon2Custom">Optional custom Argon2 settings (memory, parallelism) if different from the default snapshot.</param>
    /// <returns>An implementation of <see cref="IHashEngine"/>.</returns>
    /// <exception cref="GlitchCryptException">Thrown when an unsupported engine type is requested or settings are missing.</exception>
    public static IHashEngine Create(
        HasherEngineType engineType,
        HashStrategySnapshot settings,
        HashSettingsArgon2Snapshot? argon2Custom = null) => engineType switch
        {
            HasherEngineType.PBKDF2 => new Pbkdf2Engine(settings.HashAlgorithm, settings.Iterations),
            HasherEngineType.Argon2id => new Argon2idEngine((argon2Custom ?? settings.Argon2!).Value),
            _ => throw new GlitchCryptException($"The hasher engine type '{engineType}' is not supported.")
        };
    /* */
}