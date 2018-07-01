using JwtSharp.WebApi.Filters;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace JwtSharp.Demo.WebApi.Controllers
{

    public class TestController : ApiController
    {

        private readonly JwtIssuer jwtIssuer;

        public TestController(JwtIssuer jwtIssuer)
        {
            this.jwtIssuer = jwtIssuer;
        }

        [HttpGet, Route("token")]
        public IHttpActionResult RequestToken(string username, string password)
        {
            // Note: this is for testing only, not for production!
            // Assume all usernames are valid and password should be password
            if (password == "password")
            {
                var token = this.jwtIssuer.IssueToken(
                    "id", username,
                    "username", username,
                    "loggedInAt", DateTime.UtcNow.ToString("o"),
                    "isAdmin", (username == "admin").ToString()
                );

                return this.Ok(new
                {
                    Token = token,
                });
            }
            else
            {
                return this.BadRequest(JsonConvert.SerializeObject(new
                {
                    Error = "Incorrect Username or Password",
                }));
            }
        }

        [HttpGet, Route("public")]
        public string PublicApi()
        {
            return "Hello";
        }

        [JwtAuthentication]
        [HttpGet, Route("authorized")]
        public IEnumerable<KeyValuePair<string, string>> Authorized()
        {
            var identity = this.User.Identity as ClaimsIdentity;
            return identity.Claims
                .Select(q => new KeyValuePair<string, string>(q.Type, q.Value));
        }

        [JwtAuthentication, JwtClaimsAuthorization("isAdmin", "true", "True")]
        [HttpGet, Route("admin")]
        public IEnumerable<KeyValuePair<string, string>> AdminOnly()
        {
            var identity = this.User.Identity as ClaimsIdentity;
            return identity.Claims
                .Select(q => new KeyValuePair<string, string>(q.Type, q.Value));
        }

    }

}
