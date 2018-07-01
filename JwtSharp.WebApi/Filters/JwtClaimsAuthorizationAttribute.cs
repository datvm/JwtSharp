using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace JwtSharp.WebApi.Filters
{

    public class JwtClaimsAuthorizationAttribute : AuthorizationFilterAttribute
    {

        public string Type { get; set; }
        public string[] Value { get; set; }

        public JwtClaimsAuthorizationAttribute(string type)
        {
            this.Type = type;
        }

        public JwtClaimsAuthorizationAttribute(string type, params string[] value)
        {
            this.Type = type;
            this.Value = value;
        }

        public override Task OnAuthorizationAsync(HttpActionContext actionContext, CancellationToken cancellationToken)
        {
            var principal = actionContext.RequestContext.Principal as ClaimsPrincipal;

            if (principal == null || !principal.Identity.IsAuthenticated)
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Unauthorized);
                return Task.CompletedTask;
            }

            var claim = principal.Claims.FirstOrDefault(q => q.Type == this.Type);
            if (claim == null || (this.Value != null && !this.Value.Contains(claim.Value)))
            {
                actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Forbidden);
                return Task.CompletedTask;
            }

            return base.OnAuthorizationAsync(actionContext, cancellationToken);
        }

    }
}
