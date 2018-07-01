using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JwtSharp
{

    public sealed class JwtIssuer
    {

        private SigningCredentials signingCredential;

        public JwtIssuerOptions Options { get; private set; }
        public TokenValidationParameters TokenValidationParameters { get; private set; }

        public JwtIssuer(JwtIssuerOptions options)
        {
            this.Initialize(options);
        }

        public JwtIssuer(Action<JwtIssuerOptions> optionsAction)
        {
            var options = new JwtIssuerOptions();
            optionsAction?.Invoke(options);

            this.Initialize(options);
        }

        private void Initialize(JwtIssuerOptions options)
        {
            this.Options = options;

            this.signingCredential = new SigningCredentials(this.Options.IssuerSigningKey, this.Options.SecurityAlgorithm);

            this.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidIssuer = this.Options.Issuer,

                ValidateAudience = true,
                ValidAudience = this.Options.Audience,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = this.Options.IssuerSigningKey,

                ValidateLifetime = true,
                RequireExpirationTime = this.Options.ExpireSeconds != null,
            };
        }

        public string IssueToken(IEnumerable<KeyValuePair<string, string>> claims)
        {
            return this.IssueToken(claims
                .Select(q => new Claim(q.Key, q.Value))
                .ToArray());
        }

        public string IssueToken(params string[] claimPairs)
        {
            if (claimPairs.Length % 2 != 0)
            {
                throw new ArgumentException("Claims Pairs must have even number of elements", nameof(claimPairs));
            }

            var claims = new Claim[claimPairs.Length / 2];
            for (int i = 0; i < claimPairs.Length; i += 2)
            {
                claims[i / 2] = new Claim(claimPairs[i], claimPairs[i + 1]);
            }

            return this.IssueToken(claims);
        }

        public string IssueToken(IEnumerable<Claim> claims)
        {
            var token = new JwtSecurityToken(
                issuer: this.Options.Issuer,
                audience: this.Options.Audience,
                claims: claims,
                expires: this.GetExpirationTime(),
                signingCredentials: this.signingCredential);

            return this.WriteToken(token);
        }

        private DateTime? GetExpirationTime()
        {
            if (this.Options.ExpireSeconds == null)
            {
                return null;
            }
            else
            {
                return DateTime.Now.AddSeconds(this.Options.ExpireSeconds.Value);
            }
        }

        public string WriteToken(JwtSecurityToken token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(token);
        }

        public JwtSecurityToken ReadToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                return tokenHandler.ReadToken(token) as JwtSecurityToken;
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

                var tokenHandler = new JwtSecurityTokenHandler();
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
