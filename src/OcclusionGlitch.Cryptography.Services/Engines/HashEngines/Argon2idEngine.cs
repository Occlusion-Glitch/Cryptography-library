using Konscious.Security.Cryptography;
using OcclusionGlitch.Cryptography.Services.Interfaces;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;
using System.Security.Cryptography;

namespace OcclusionGlitch.Cryptography.Services.Engines.HashEngines;

/// <summary>
/// Provides an Argon2id implementation of the hash engine. Argon2id is the memory-hard 
/// winner of the Password Hashing Competition, offering superior resistance against GPU/ASIC attacks.
/// </summary>
/// <param name="settings">The snapshot of Argon2 hashing settings, including memory size and parallelism.</param>
internal sealed class Argon2idEngine(HashSettingsArgon2Snapshot settings) : IHashEngine
{
    // === CLIENT METHODS === /* */
    /// <summary>
    /// Computes an Argon2id hash using the configured memory, parallelism, and iterations.
    /// </summary>
    /// <param name="data">The input data (password) buffer.</param>
    /// <param name="salt">The salt or pepper buffer.</param>
    /// <param name="hash">The output buffer for the resulting hash.</param>
    public void ComputeHash(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> salt,
        Span<byte> hash)
    {
        // Argon2 implementations often require byte arrays. 
        // We carefully manage these temporary allocations.
        byte[] dataArray = data.ToArray();
        byte[] saltArray = salt.ToArray();

        try
        {
            // Create an Argon2id instance with the specified parameters.
            using var argon2 = new Argon2id(dataArray)
            {
                Salt = saltArray,
                DegreeOfParallelism = settings.Parallelism,
                MemorySize = settings.MemorySizeKb,
                Iterations = settings.Iterations
            };

            byte[] result = argon2.GetBytes(hash.Length);
            try
            {
                result.CopyTo(hash);
            }
            finally
            {
                // Wipe the result array as soon as it's copied
                CryptographicOperations.ZeroMemory(result);
            }
        }
        finally
        {
            // Wipe sensitive data buffers after use
            CryptographicOperations.ZeroMemory(dataArray);
            CryptographicOperations.ZeroMemory(saltArray);
        }
    }

    /// <summary>
    /// Argon2id does not require any special disposal logic since we are using 'using' statements to manage resources.
    /// </summary>
    public void Dispose()
    {
        // Argon2id instance is disposed within ComputeHash using 'using'
    }
    /* */
}