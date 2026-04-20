using Microsoft.Extensions.DependencyInjection;
using OcclusionGlitch.Cryptography.Contracts.Interfaces;
using OcclusionGlitch.Cryptography.Services;

namespace OcclusionGlitch.Cryptography.Kernel;

public static class GlitchCryptExtensions
{
    public static GlitchCryptBuilder AddGlitchCryptography(this IServiceCollection services)
    {
        // === SERVICES SECTION ===
        services.AddSingleton<ICryptService, CryptService>();
        services.AddSingleton<IHashService, HashService>();
        services.AddSingleton<IBlindIndexService, BlindIndexService>();
        return new GlitchCryptBuilder(services);
    }
}