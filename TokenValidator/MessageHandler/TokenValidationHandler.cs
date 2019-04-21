using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace TokenValidator.MessageHandler
{
    public class TokenValidationHandler : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var statusCode = HttpStatusCode.Unauthorized;
            var token = request.Headers.Authorization;

            if (!token.Scheme.Equals("bearer", StringComparison.CurrentCultureIgnoreCase))
                return Task<HttpResponseMessage>.Factory.StartNew(() => new HttpResponseMessage(statusCode) { },
                    cancellationToken);

            var claimPrincipal = Validate(token.Parameter);

            if (claimPrincipal == null)
                return Task<HttpResponseMessage>.Factory.StartNew(() => new HttpResponseMessage(statusCode) { },
                    cancellationToken);

            Thread.CurrentPrincipal = claimPrincipal;
            HttpContext.Current.User = claimPrincipal;

            return base.SendAsync(request, cancellationToken);
        }

        private ClaimsPrincipal Validate(string token)
        {
            var audience = "testRelam";
            var issuer = "http://testIDServer/samples";
            var signingKey = "testSigningKey";
            try
            {
                SecurityToken securityToken;

                var validationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(signingKey)),
                    ValidAudience = audience,
                    ValidIssuer = issuer,
                    ValidateLifetime = true

                };

                var handler = new JwtSecurityTokenHandler();

                return handler.ValidateToken(token, validationParameters, out securityToken);
            }
            catch (Exception ex)
            {
                return null;
            }

        }
    }
}