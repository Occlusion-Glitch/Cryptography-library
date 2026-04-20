using Microsoft.Extensions.Options;
using OcclusionGlitch.Cryptography.Contracts.Exceptions;
using OcclusionGlitch.Cryptography.Contracts.Interfaces;
using OcclusionGlitch.Cryptography.Contracts.Options;
using OcclusionGlitch.Cryptography.Contracts.Snapshots;
using OcclusionGlitch.Cryptography.Services.Factories;
using OcclusionGlitch.Cryptography.Services.Interfaces;
using OcclusionGlitch.Cryptography.Services.Internal.Enums;
using OcclusionGlitch.Cryptography.Services.Internal.Providers;
using OcclusionGlitch.Cryptography.Services.Internal.Snapshots;
using System.Security.Cryptography;
using System.Text;

namespace OcclusionGlitch.Cryptography.Services;

public class CryptService(
    IOptions<GlitchCryptOptions> options,
    IKeyProvider keyProvider
    ) : ICryptService
{
    // === PRIVATE PROPERTIES === /* */
    private readonly int _bytesHeaderOffset = 3; // 1 byte for version + 2 bytes for key version
    private readonly int _base64HeaderOffset = 4; // Base64 encoding expands data, so we need to account for that in the offset
    private readonly GlitchCryptOptions _options = options.Value;
    /* */

    // === CLEINT METHODS === /* */
    public CryptResultSnapshot EncryptTarget(string plainText, string? associatedData = null)
    {
        // Check if the plain text is valid
        if (string.IsNullOrEmpty(plainText)) throw new GlitchCryptException("Plain text cannot be empty.");

        // Check if the key provider is available and can provide a key
        byte[] keyBytes = keyProvider.GetCryptKey(_options.TargetCryptKeyVersion);
        if (keyBytes.Length == 0) throw new GlitchCryptException("Key provider returned an empty key.");

        // Get current settings
        var currentSettings = CryptStrategyProvider.GetStrategy(_options.TargetCryptStrategyId);

        // Encrypt the plain text
        byte[] dataBytes = Encoding.UTF8.GetBytes(plainText);

        // Generate random salt, nonce, and tag
        byte[] salt = RandomNumberGenerator.GetBytes(currentSettings.SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(currentSettings.NonceSize);
        byte[] tag = new byte[currentSettings.TagSize];
        var clipherTextLetgth = GetCipherTextLength(dataBytes.Length, currentSettings.EngineType);
        byte[] cipherText = new byte[clipherTextLetgth];

        // Derive the encryption key using HKDF
        Span<byte> derivedKey = stackalloc byte[currentSettings.KeySize];
        try
        {
            HKDF.DeriveKey(currentSettings.KdfHashAlgorithm, keyBytes, derivedKey, salt, ReadOnlySpan<byte>.Empty);

            // Encrypt the data using AES-GCM
            using (ICryptEngine engine = CryptEngineFactory.Create(currentSettings.EngineType, derivedKey, currentSettings.TagSize))
            {
                if (!string.IsNullOrWhiteSpace(associatedData))
                {
                    var adBytes = Encoding.UTF8.GetBytes(associatedData);
                    engine.Encrypt(nonce, dataBytes, cipherText, tag, adBytes);
                }
                else
                    engine.Encrypt(nonce, dataBytes, cipherText, tag);
            }

            // Package the final result: [strategyId (1 byte)] [key version (2 bytes)] [salt] [nonce] [tag] [cipher text]
            int offset = _bytesHeaderOffset;
            byte[] finalPackage = new byte[GetTotalPackageLength(clipherTextLetgth, currentSettings)];

            // Fill the package
            Span<byte> pack = finalPackage;
            // Set header: strategyId and key version
            pack[0] = _options.TargetCryptStrategyId;
            pack[1] = (byte)(_options.TargetCryptKeyVersion >> 8);
            pack[2] = (byte)(_options.TargetCryptKeyVersion & 0xFF);
            // Copy all other information
            salt.CopyTo(pack.Slice(offset, currentSettings.SaltSize));
            offset += currentSettings.SaltSize;
            nonce.CopyTo(pack.Slice(offset, currentSettings.NonceSize));
            offset += currentSettings.NonceSize;
            tag.CopyTo(pack.Slice(offset, currentSettings.TagSize));
            offset += currentSettings.TagSize;
            cipherText.CopyTo(pack.Slice(offset, cipherText.Length));

            // Formatting result
            var fullCipher = Convert.ToBase64String(finalPackage);
            return new CryptResultSnapshot(fullCipher, fullCipher.Substring(0, _base64HeaderOffset));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedKey);
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }
    public DecryptResultSnapshot Decrypt(string inputCipherText, string? associatedData = null)
    {
        // Check if the input is valid
        if (string.IsNullOrWhiteSpace(inputCipherText))
            throw new GlitchCryptException("Cipher text cannot be null or empty.");

        // Decode the Base64 string to get the full package
        byte[] fullPackage = FromBase64String(inputCipherText);
        if (fullPackage.Length < _bytesHeaderOffset)
            throw new GlitchCryptException("Payload is too short to contain metadata header.");

        // Get algorithm settings based on the version byte
        var strategyId = fullPackage[0];
        var rawSettings = CryptStrategyProvider.GetStrategy(strategyId);

        // Validate that the package has enough data to contain all required cryptographic components
        PackageMinLengthValidate(fullPackage, rawSettings);

        byte[]? keyBytes = null;
        byte[]? decryptedData = null;
        Span<byte> derivedKey = stackalloc byte[rawSettings.KeySize];
        try
        {
            int offset = _bytesHeaderOffset;
            // Unpack the data: [strategyId (1 byte)] [key version (2 bytes)] [salt] [nonce] [tag] [cipher text]
            ReadOnlySpan<byte> pack = fullPackage;
            ReadOnlySpan<byte> salt = pack.Slice(offset, rawSettings.SaltSize);
            offset += rawSettings.SaltSize;
            ReadOnlySpan<byte> nonce = pack.Slice(offset, rawSettings.NonceSize);
            offset += rawSettings.NonceSize;
            ReadOnlySpan<byte> tag = pack.Slice(offset, rawSettings.TagSize);
            offset += rawSettings.TagSize;
            ReadOnlySpan<byte> cipherText = pack.Slice(offset);

            // Derive the decryption key using HKDF
            ushort keyVersion = (ushort)((pack[1] << 8) | pack[2]);
            keyBytes = keyProvider.GetCryptKey(keyVersion);
            HKDF.DeriveKey(rawSettings.KdfHashAlgorithm, keyBytes, derivedKey, salt, ReadOnlySpan<byte>.Empty);

            // Get engine instance to validate the parameters (this will throw if parameters are invalid)
            decryptedData = new byte[cipherText.Length];
            using (ICryptEngine engine = CryptEngineFactory.Create(rawSettings.EngineType, derivedKey, rawSettings.TagSize))
            {
                if (!string.IsNullOrWhiteSpace(associatedData))
                {
                    byte[] adBytes = Encoding.UTF8.GetBytes(associatedData);
                    engine.Decrypt(nonce, cipherText, decryptedData, tag, adBytes);
                }
                else engine.Decrypt(nonce, cipherText, decryptedData, tag);
            }

            // Decryption successful, convert to string and return
            var plainText = Encoding.UTF8.GetString(decryptedData);
            bool requiresRotation = strategyId != _options.TargetCryptStrategyId || keyVersion != _options.TargetCryptKeyVersion;
            return new DecryptResultSnapshot(plainText, requiresRotation, inputCipherText.Substring(0, _base64HeaderOffset));
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new GlitchCryptException("Decryption failed due to authentication tag mismatch. Data may be corrupted or tampered with.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(derivedKey);
            if (decryptedData != null) CryptographicOperations.ZeroMemory(decryptedData);
            if (keyBytes != null) CryptographicOperations.ZeroMemory(keyBytes);
        }
    }
    /* */

    // === PRIVATE METHODS === /* */
    // Format of the package: [strategyId (1 byte)] [key version (2 bytes)] [salt] [nonce] [tag] ...
    private void PackageMinLengthValidate(byte[] fullCipherText, CryptStrategySnapshot settings)
    {
        // Check if the package is long enough to contain the header
        int minLength = _base64HeaderOffset + settings.SaltSize + settings.NonceSize + settings.TagSize;
        if (fullCipherText.Length < minLength)
            throw new GlitchCryptException("Payload is missing required cryptographic components.");
    }
    private int GetCipherTextLength(int plaintextLength, CipherEngineType engineType)
        => engineType switch
        {
            CipherEngineType.AesGcm => plaintextLength, // AES-GCM does not expand the ciphertext (tag is separate)
            CipherEngineType.ChaCha20Poly1305 => plaintextLength, // ChaCha20-Poly1305 also does not expand the ciphertext (tag is separate)
            _ => throw new GlitchCryptException("Unsupported cipher engine type.")
        };
    private int GetTotalPackageLength(int cipherTextLength, CryptStrategySnapshot settings) => _bytesHeaderOffset + settings.SaltSize + settings.NonceSize + settings.TagSize + cipherTextLength;
    private byte[] FromBase64String(string base64)
    {
        try { return Convert.FromBase64String(base64); }
        catch (FormatException) { throw new GlitchCryptException("Invalid hashed package format. Must be a valid Base64 string."); }
    }
    /* */
}