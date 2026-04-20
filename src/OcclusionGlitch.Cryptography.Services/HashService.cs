using Microsoft.Extensions.Options;
using OcclusionGlitch.Cryptography.Contracts.Interfaces;
using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Contracts.Options;
using OcclusionGlitch.Cryptography.Contracts.Snapshots;
using OcclusionGlitch.Cryptography.Services.Factories;
using OcclusionGlitch.Cryptography.Services.Internal.Providers;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;
using System.Security.Cryptography;
using System.Text;

namespace OcclusionGlitch.Cryptography.Services;

public class HashService(
    IOptions<GlitchCryptOptions> options,
    IKeyProvider keyProvider
    ) : IHashService
{
    // === PRIVATE PROPERTIES === /* */
    private readonly int _bytesOffsetSize = 3; // 1 byte for version + 2 bytes for key version
    private readonly int _base64OffsetSize = 4; // Base64 encoding expands data, so we need to account for that in the offset
    private readonly GlitchCryptOptions _options = options.Value;
    /* */

    // === CLIENT METHODS === /* */
    public HashResultSnapshot GenerateTargetHash(string plainText)
    {
        ValidatePlainText(plainText);

        // Get the current settings based on the version specified in options
        var settings = HashStrategyProvider.GetStrategy(_options.TargetHashStrategyId);
        byte[] pepperBytes = GetPepperHashKey(_options.TargetPepperKeyVersion);
        byte[] salt = GenerateRawSalt(settings.SaltSize);
        byte[] keyedInput = PrepareInput(plainText, pepperBytes);

        Span<byte> hashBuffer = stackalloc byte[settings.HashSize];
        try
        {
            // Get the hash engine based on the settings and compute the hash using the data and pepper
            using (var engine = HashEngineFactory.Create(settings.HashEngineType, settings, argon2Custom: GetArgon2FromOptions()))
                engine.ComputeHash(keyedInput, salt, hashBuffer);

            // Format the result: [version][PepperKeyVersion][salt][hash]
            byte[] finalPackage = new byte[_bytesOffsetSize + settings.SaltSize + settings.HashSize];
            finalPackage[0] = _options.TargetHashStrategyId;
            finalPackage[1] = (byte)(_options.TargetPepperKeyVersion >> 8);
            finalPackage[2] = (byte)(_options.TargetPepperKeyVersion & 0xFF);
            // Copy the salt and hash into the final package
            salt.CopyTo(finalPackage.AsSpan(_bytesOffsetSize, settings.SaltSize));
            hashBuffer.CopyTo(finalPackage.AsSpan(_bytesOffsetSize + settings.SaltSize));

            // Convert the final package to Base64 for storage or transmission
            var finalBase64 = Convert.ToBase64String(finalPackage);
            return new HashResultSnapshot(finalBase64, finalBase64.Substring(0, _base64OffsetSize));
        }
        finally
        {
            // Clear sensitive data from memory
            CryptographicOperations.ZeroMemory(keyedInput);
            CryptographicOperations.ZeroMemory(pepperBytes);
        }
    }
    public VerifyHashResultSnapshot VerifyHash(string plainText, string hashedPackage)
    {
        ValidatePlainText(plainText);
        if (string.IsNullOrWhiteSpace(hashedPackage))
            throw new GlitchCryptException("Hashed package cannot be null or empty.");

        // Get the full package from Base64 and extract the version and key version
        byte[] fullPackage = FromBase64String(hashedPackage);
        if (fullPackage.Length < _bytesOffsetSize)
            throw new GlitchCryptException("Invalid hashed package format. Package is too short to contain required metadata.");

        // Get the algorithm version and key version from the package
        byte strategyId = fullPackage[0];
        ushort keyVersion = (ushort)((fullPackage[1] << 8) | fullPackage[2]);

        // Get the settings and pepper based on the extracted versions
        var settings = HashStrategyProvider.GetStrategy(strategyId);
        if (fullPackage.Length != _bytesOffsetSize + settings.SaltSize + settings.HashSize)
            throw new GlitchCryptException("Invalid hashed package format. Package length does not match expected size based on metadata.");

        // Pepper key retrieval based on the key version from the package
        byte[] pepperBytes = GetPepperHashKey(keyVersion);

        // Unpack the salt and original hash from the package
        ReadOnlySpan<byte> salt = fullPackage.AsSpan(_bytesOffsetSize, settings.SaltSize);
        ReadOnlySpan<byte> originalHash = fullPackage.AsSpan(_bytesOffsetSize + settings.SaltSize);
        byte[] keyedInput = PrepareInput(plainText, pepperBytes);

        // Compute the hash using the same settings, salt, and pepper
        Span<byte> computedHash = stackalloc byte[settings.HashSize];
        try
        {
            // Get the hash engine based on the settings and compute the hash using the data and pepper
            using (var engine = HashEngineFactory.Create(settings.HashEngineType, settings, argon2Custom: GetArgon2FromOptions()))
                engine.ComputeHash(keyedInput, salt, computedHash);

            // Compare the original hash with the computed hash in a time-constant manner
            var isMatch = CryptographicOperations.FixedTimeEquals(originalHash, computedHash);
            bool isRotationRequired = (strategyId != _options.TargetHashStrategyId) ||
                                      (keyVersion != _options.TargetPepperKeyVersion);
            return new VerifyHashResultSnapshot(isMatch, isRotationRequired, hashedPackage.Substring(0, _base64OffsetSize));
        }
        finally
        {
            // Clear sensitive data from memory
            CryptographicOperations.ZeroMemory(keyedInput);
            CryptographicOperations.ZeroMemory(pepperBytes);
        }
    }
    /* */

    // === PRIVATE METHODS === /* */
    private HashSettingsArgon2Snapshot? GetArgon2FromOptions()
    {
        // If Argon2 is not the selected strategy, we can skip this step
        if (_options.Argon2Options == null) return null;

        // For Argon2, we need to extract the specific settings from the options to pass to the hash
        var argon2options = _options.Argon2Options;
        if (argon2options.Iterations <= 0) throw new GlitchCryptException("Argon2 iterations must be greater than 0.");
        if (argon2options.MemorySizeKiB <= 0) throw new GlitchCryptException("Argon2 memory size must be greater than 0.");
        if (argon2options.DegreeOfParallelism <= 0) throw new GlitchCryptException("Argon2 degree of parallelism must be greater than 0.");

        // Settings are valid, return the snapshot to be used by the hash engine
        return new HashSettingsArgon2Snapshot(argon2options.MemorySizeKiB, argon2options.DegreeOfParallelism, argon2options.Iterations);
    }
    private byte[] GenerateRawSalt(int saltSize) => RandomNumberGenerator.GetBytes(saltSize);
    private void ValidatePlainText(string plainText)
    {
        // Check if the plain text is null or empty
        if (string.IsNullOrWhiteSpace(plainText))
            throw new GlitchCryptException("Plain text cannot be null.");
    }
    private byte[] GetPepperHashKey(ushort keyVersion)
    {
        byte[] pepperBytes = keyProvider.GetPepperKey(keyVersion);
        if (pepperBytes.Length == 0) throw new GlitchCryptException("Hash key cannot be empty.");
        return pepperBytes;
    }
    private byte[] PrepareInput(string plainText, byte[] pepper)
    {
        string normalizedText = plainText.Normalize(NormalizationForm.FormC);
        byte[] dataBytes = Encoding.UTF8.GetBytes(normalizedText);
        try
        {
            using var hmac = new HMACSHA256(pepper);
            return hmac.ComputeHash(dataBytes);
        }
        finally { CryptographicOperations.ZeroMemory(dataBytes); }
    }
    private byte[] FromBase64String(string base64)
    {
        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException) { throw new GlitchCryptException("Invalid hashed package format. Must be a valid Base64 string."); }
    }
    /* */
}