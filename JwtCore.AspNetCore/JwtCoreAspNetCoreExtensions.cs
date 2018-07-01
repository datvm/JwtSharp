using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace JwtCore.AspNetCore
{
    public static class JwtCoreAspNetCoreExtensions
    {

        public static IServiceCollection AddJwtIssuerAndBearer(this IServiceCollection services, JwtIssuerOptions options)
        {
            var jwtIssuer = new JwtIssuer(options);
            services.AddSingleton(jwtIssuer);

            services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.TokenValidationParameters = jwtIssuer.TokenValidationParameters;
                });

            return services;
        }

        public static IServiceCollection AddJwtIssuerAndBearer(this IServiceCollection services, Action<JwtIssuerOptions> optionsAction)
        {
            var options = new JwtIssuerOptions();
            optionsAction?.Invoke(options);

            return AddJwtIssuerAndBearer(services, options);
        }
        
    }
}
