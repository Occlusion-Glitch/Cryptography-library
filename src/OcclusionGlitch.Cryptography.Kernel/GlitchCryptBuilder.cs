using Microsoft.Extensions.DependencyInjection;
using OcclusionGlitch.Cryptography.Kernel.Interfaces;

namespace OcclusionGlitch.Cryptography.Kernel;

public class GlitchCryptBuilder : IGlitchCryptBuilder
{
    public IServiceCollection Services { get; }
    public GlitchCryptBuilder(IServiceCollection services) => Services = services;
}
