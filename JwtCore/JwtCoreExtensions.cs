using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace JwtCore
{

    public static class JwtCoreExtensions
    {

        public static IServiceCollection AddJwtBearer(this IServiceCollection services, JwtIssuerOptions options)
        {
            services
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer= options.Issuer,
                        ValidAudience = options.Audience,
                        IssuerSigningKey =  options.IssuerSigningKey,
                    };
                });

            return services;
        }

        public static IServiceCollection AddJwtBearer(this IServiceCollection services, Func<JwtIssuerOptions> options)
        {
            return AddJwtBearer(services, options());
        }

    }

}
