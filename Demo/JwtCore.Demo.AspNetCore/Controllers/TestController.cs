using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtCore.Demo.AspNetCore.Controllers
{

    [ApiController]
    public class TestController : ControllerBase
    {

        private readonly JwtIssuer jwtIssuer;

        public TestController(JwtIssuer jwtIssuer)
        {
            this.jwtIssuer = jwtIssuer;
        }

        [HttpGet, Route("token")]
        public IActionResult RequestToken(string username, string password)
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
                return this.BadRequest(new
                {
                    Error = "Incorrect Username or Password",
                });
            }
        }

        [HttpGet, Route("public")]
        public string PublicApi()
        {
            return "Hello";
        }

        [Authorize]
        [HttpGet, Route("authorized")]
        public IEnumerable<KeyValuePair<string, string>> Authorized()
        {
            return this.User.Claims
                .Select(q => new KeyValuePair<string, string>(q.Type, q.Value));
        }

        [Authorize(Policy = "AdminOnly")]
        [HttpGet, Route("admin")]
        public IEnumerable<KeyValuePair<string, string>> AdminOnly()
        {
            return this.User.Claims
                .Select(q => new KeyValuePair<string, string>(q.Type, q.Value));
        }

    }

}