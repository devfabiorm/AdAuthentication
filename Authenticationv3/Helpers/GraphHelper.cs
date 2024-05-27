using Authenticationv3.Models;
using Authenticationv3.Providers;
using Microsoft.Graph;
using Microsoft.Kiota.Abstractions.Authentication;
using System.Threading.Tasks;

namespace Authenticationv3.Helpers
{
    public static class GraphHelper
    {
        public static async Task<CacheUser> GetUserDetailsAsync()
        {
            var authenticationProvider = new BaseBearerTokenAuthenticationProvider(new TokenProvider());
            var graphClient = new GraphServiceClient(authenticationProvider);

            var user = await graphClient.Me
                .GetAsync((requestConfiguration) =>
                    requestConfiguration.QueryParameters.Select = new string[]
                    {
                        "displayName",
                        "mail",
                        "UserPrincipalName",
                        "identities"
                    });

            return new CacheUser
            {
                Avatar = string.Empty,
                DisplayName = user.DisplayName,
                Email = string.IsNullOrEmpty(user.Mail) ?
                    user.UserPrincipalName : user.Mail
            };
        }
    }
}