using Microsoft.Extensions.DependencyInjection;

namespace OcclusionGlitch.Cryptography.Kernel.Interfaces;

public interface IGlitchCryptBuilder
{
    // === CLIENT METHODS === /* */
    IServiceCollection Services { get; }
    /* */
}
