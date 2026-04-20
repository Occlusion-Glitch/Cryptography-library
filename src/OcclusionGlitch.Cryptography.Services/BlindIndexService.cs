
using Microsoft.Extensions.Options;
using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Contracts.Interfaces;
using OcclusionGlitch.Cryptography.Contracts.Options;
using OcclusionGlitch.Cryptography.Contracts.Snapshots;
using OcclusionGlitch.Cryptography.Services.Factories;
using OcclusionGlitch.Cryptography.Services.Interfaces;
using OcclusionGlitch.Cryptography.Services.Internal.Providers;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace OcclusionGlitch.Cryptography.Services;

public class BlindIndexService(
    IOptions<GlitchCryptOptions> options,
    IKeyProvider keyProvider
    ) : IBlindIndexService
{
    // === PRIVATE PROPERTIES === /* */
    private readonly int _bytesOffsetSize = 3; // 1 byte for version + 2 bytes for key version
    private readonly int _base64OffsetSize = 4; // Base64 encoding expands data, so we need to account for that in the offset
    private readonly GlitchCryptOptions _options = options.Value;
    /* */

    // === CLIENT METHODS === /* */
    public BlindIndexResultSnapshot GenerateSearchIndices(string plainText)
    {
        ValidatePlainText(plainText);

        // Generate blind indices for the plain text and store them in the list
        var builder = ImmutableArray.CreateBuilder<BlindIndexSnapshot>();
        builder.Add(CreateBlindIndexSnapshot(plainText, _options.TargetPepperKeyVersion, false));

        // Add legacy blind indices for all previous pepper key versions (if any) to the list
        if (_options.LegacyPepperKeyVersions != null && _options.LegacyPepperKeyVersions.Length > 0)
            foreach (var legacyKeyVersion in _options.LegacyPepperKeyVersions)
                if (legacyKeyVersion != _options.TargetPepperKeyVersion) // Avoid adding the target index twice if it's also listed as a legacy version
                    builder.Add(CreateBlindIndexSnapshot(plainText, legacyKeyVersion, requiresRotation: true));

        // Return the result with all generated blind indices and a flag indicating if any of them require rotation
        return new BlindIndexResultSnapshot(builder.ToImmutable(), builder.Any(i => i.RequiresRotation));
    }
    public BlindIndexSnapshot GenerateTargetBlindIndex(string plainText)
    {
        ValidatePlainText(plainText);

        // Generate a blind index for the plain text using the pepper key version specified in options
        return CreateBlindIndexSnapshot(plainText, _options.TargetPepperKeyVersion, requiresRotation: false);
    }
    /* */

    // === PRIVATE METHODS === /* */
    private BlindIndexSnapshot CreateBlindIndexSnapshot(string plainText, ushort pepperKeyVersion, bool requiresRotation)
    {
        // Get the blind index strategy settings based on the strategy ID specified in options
        var strategy = BlindIndexStrategyProvider.GetStrategy(_options.TargetBlindIndexStrategyId);

        // Get the pepper key based on the strategyId specified in options
        byte[] pepperBytes = GetPepperHashKey(pepperKeyVersion);
        byte[] keyedInput = PrepareInput(plainText, pepperBytes, strategy);

        // Format the result: [strategyId][PepperKeyVersion][hash]
        byte[] package = new byte[_bytesOffsetSize + strategy.OutputSize];
        package[0] = _options.TargetBlindIndexStrategyId;
        package[1] = (byte)(pepperKeyVersion >> 8);
        package[2] = (byte)(pepperKeyVersion & 0xFF);
        // Copy the keyed input into the package (truncated to outputSize)
        Buffer.BlockCopy(keyedInput, 0, package, _bytesOffsetSize, strategy.OutputSize);

        // Clear sensitive data from memory
        CryptographicOperations.ZeroMemory(keyedInput);
        CryptographicOperations.ZeroMemory(pepperBytes);

        // Convert the package to Base64 for storage or transmission
        var fullBlindIndex = Convert.ToBase64String(package);
        return new BlindIndexSnapshot(fullBlindIndex, requiresRotation, fullBlindIndex.Substring(0, _base64OffsetSize));
    }
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
    private byte[] PrepareInput(string plainText, byte[] pepper, BlindIndexStrategySnapshot settings)
    {
        // Normalize the plain text to ensure consistent hashing (e.g., NFC normalization)
        string normalizedText = plainText.Normalize(NormalizationForm.FormC);
        byte[] dataBytes = Encoding.UTF8.GetBytes(normalizedText);

        // Allocate a buffer for the final hash result
        byte[] finalHash = new byte[settings.OutputSize];
        try
        {
            // Create a blind index engine based on the specified hash algorithm and pepper
            using (IBlindIndexEngine engine = BlindIndexEngineFactory.Create(settings.HashAlgorithm, pepper))
            {
                // Allocate a buffer for the full hash output
                Span<byte> fullHashBuffer = stackalloc byte[engine.HashSize];

                // Compute the hash of the data using the blind index engine
                engine.ComputeHash(dataBytes, fullHashBuffer);
                // Copy only the required number of bytes from the full hash to the final hash buffer
                fullHashBuffer.Slice(0, settings.OutputSize).CopyTo(finalHash);
            }

            return finalHash;
        }
        finally { CryptographicOperations.ZeroMemory(dataBytes); }
    }
    /* */
}