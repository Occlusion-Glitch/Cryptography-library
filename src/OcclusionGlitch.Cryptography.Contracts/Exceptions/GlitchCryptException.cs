namespace OcclusionGlitch.Cryptography.Contracts.Exceptions;

/// <summary>
/// The base exception for all cryptographic and hashing operations within the GlitchCrypt system.
/// Use this to distinguish domain-specific security failures from general system exceptions.
/// </summary>
public class GlitchCryptException : Exception
{
    // === CONSTRUCTORS === /* */
    public GlitchCryptException() : base() { }
    public GlitchCryptException(string message) : base(message) { }
    public GlitchCryptException(string message, Exception innerException) : base(message, innerException) { }
    /* */
}