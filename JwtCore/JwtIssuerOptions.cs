using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace JwtCore
{
    public class JwtIssuerOptions
    {

        public string SecurityAlgorithm { get; set; } = SecurityAlgorithms.HmacSha256;
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int ExpireSeconds { get; set; } = 1800;

        public string SecurityKey
        {
            get
            {
                return this.securityKeyField;
            }
            set
            {
                this.securityKeyField = value;
                this.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(value));
            }
        }

        public SymmetricSecurityKey IssuerSigningKey { get; private set; }

        private string securityKeyField;

    }
}
