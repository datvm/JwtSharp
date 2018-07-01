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

        internal JwtIssuerOptions options { get; private set; }
        private SigningCredentials signingCredential;
        private JwtSecurityTokenHandler jwtTokenHandler;

        public SymmetricSecurityKey SigningKey
        {
            get
            {
                return this.options.IssuerSigningKey;
            }
        }

        public JwtIssuer(JwtIssuerOptions options)
        {
            this.options = options;

            this.signingCredential = new SigningCredentials(this.SigningKey, this.options.SecurityAlgorithm);
            this.jwtTokenHandler = new JwtSecurityTokenHandler();
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
                issuer: this.options.Issuer,
                audience: this.options.Audience,
                claims: claims,
                expires: DateTime.Now.AddSeconds(this.options.ExpireSeconds),
                signingCredentials: this.signingCredential);

            return this.jwtTokenHandler.WriteToken(token);
        }

    }

}
