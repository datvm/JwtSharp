using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JwtCore
{

    public sealed class JwtIssuer
    {

        private SigningCredentials signingCredential;
        private JwtSecurityTokenHandler tokenHandler;

        public JwtIssuerOptions Options { get; private set; }
        public TokenValidationParameters TokenValidationParameters { get; private set; }

        public JwtIssuer(JwtIssuerOptions options)
        {
            this.Options = options;

            this.signingCredential = new SigningCredentials(this.Options.IssuerSigningKey, this.Options.SecurityAlgorithm);
            this.tokenHandler = new JwtSecurityTokenHandler();

            this.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = this.Options.Issuer,

                ValidateAudience = true,
                ValidAudience = this.Options.Audience,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = this.Options.IssuerSigningKey,

                ValidateLifetime = true,
                RequireExpirationTime = true,
            };
        }

        public JwtIssuer(Func<JwtIssuerOptions> options) : this(options()) { }

        public string IssueToken(params KeyValuePair<string, string>[] claims)
        {
            return this.IssueToken(claims
                .Select(q => new Claim(q.Key, q.Value))
                .ToArray());
        }

        public string IssueToken(params Claim[] claims)
        {
            var token = new JwtSecurityToken(
                issuer: this.Options.Issuer,
                audience: this.Options.Audience,
                claims: claims,
                expires: DateTime.Now.AddSeconds(this.Options.ExpireSeconds),
                signingCredentials: this.signingCredential);

            return this.tokenHandler.WriteToken(token);
        }

        public JwtSecurityToken ReadToken(string token)
        {
            try
            {
                return this.tokenHandler.ReadToken(token) as JwtSecurityToken;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                if (token == null)
                {
                    return null;
                }

                var principal = tokenHandler.ValidateToken(
                    token,
                    this.TokenValidationParameters,
                    out var securityToken);

                return principal;
            }
            catch (Exception)
            {
                return null;
            }
        }

    }

}
