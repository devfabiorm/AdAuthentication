using Microsoft.Kiota.Abstractions.Authentication;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Authenticationv3.Providers
{
    public class TokenProvider : IAccessTokenProvider
    {
        public async Task<string> GetAuthorizationTokenAsync(Uri uri, Dictionary<string, object> additionalAuthenticationContext = default,
            CancellationToken cancellationToken = default)
        {
            var claims = ClaimsPrincipal.Current;

            var homeAccountId = claims.FindFirst(c => c.Type == "aid")?.Value;

            var account = await AuthenticationProvider.GetAccountAsync(homeAccountId);

            string[] graphScopes = ConfigurationManager.AppSettings["AppScopes"].Split(' ');

            var tokens = await AuthenticationProvider.GetApplicationTokensAsync(graphScopes, account: account);
            return tokens.AccessToken;
        }

        public AllowedHostsValidator AllowedHostsValidator { get; }
    }
}