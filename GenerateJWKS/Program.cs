using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using GenerateJWKS.Repositories.Interfaces;
using GenerateJWKS.Repositories;

namespace GenerateJWKS
{
    public static class Program
    {
        static void Main(string[] args)
        {
            Host.CreateDefaultBuilder()
                .ConfigureServices(ConfigureServices)
                .ConfigureServices(services => services.AddSingleton<App>())
                .Build()
                .Services
                .GetService<App>()
                .RunAsync()
                .Wait();
        }
        private static void ConfigureServices(IServiceCollection services)
        {
            services.AddScoped<IJwkGenerator, JwkGenerator>();
        }
    }
}
