using AdAuthentication.Models;
using AdAuthentication.TokenStorage;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using System.Collections.Generic;
using System.Configuration;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace AdAuthentication.Helpers
{
    public static class GraphHelper
    {
        private static readonly string appId = ConfigurationManager.AppSettings["AppId"];
        private static readonly string appSecret = ConfigurationManager.AppSettings["AppSecret"];
        private static readonly string redirectUri = ConfigurationManager.AppSettings["RedirectUri"];
        private static readonly string tenant = ConfigurationManager.AppSettings["Tenant"];

        private static readonly List<string> graphScopes = new List<string>(ConfigurationManager.AppSettings["AppScopes"].Split(' '));

        public static async Task<IEnumerable<Event>> GetEventsAsync()
        {
            string authority = string.Format(System.Globalization.CultureInfo.InvariantCulture, ConfigurationManager.AppSettings["Authority"], tenant);
            var idClient = ConfidentialClientApplicationBuilder.Create(appId)
                        .WithRedirectUri(redirectUri)
                        .WithClientSecret(appSecret)
                        .WithAuthority(authority)
                        .Build();

            var tokenStore = new SessionTokenCustomCache(idClient.UserTokenCache, HttpContext.Current);

            var userUniqueId = tokenStore.GetUsersUniqueId(ClaimsPrincipal.Current);
            var account = await idClient.GetAccountAsync(userUniqueId);

            // By calling this here, the token can be refreshed
            // if it's expired right before the Graph call is made
            var result = await idClient.AcquireTokenSilent(graphScopes, account)
                .ExecuteAsync();

            var graphClient = new GraphServiceClient(
                new DelegateAuthenticationProvider(
                    async (requestMessage) =>
                    {
                        requestMessage.Headers.Authorization =
                            new AuthenticationHeaderValue("Bearer", result.AccessToken);
                    }));

            //It's only possible retrieve events from accounts internal to your organization
            //Or from external organization which have added your app in their own tenant and grant the permission
            //Refer to https://learn.microsoft.com/en-us/answers/questions/1160468/microsoft-graph-api-how-to-access-guest-calendar-e
            var events = await graphClient.Me.Events.Request()
                .Select("subject,organizer,start,end")
                .OrderBy("createdDateTime DESC")
                .GetAsync();

            return events.CurrentPage;
        }

        public static async Task<CachedUser> GetUserDetailsAsync(string accessToken, string accountId)
        {
            var graphClient = new GraphServiceClient(
                new DelegateAuthenticationProvider(
                    async (requestMessage) =>
                    {
                        requestMessage.Headers.Authorization =
                            new AuthenticationHeaderValue("Bearer", accessToken);
                    }));

            var user = await graphClient.Me.Request()
                .Select(u => new
                {
                    u.DisplayName,
                    u.Mail,
                    u.UserPrincipalName
                })
                .GetAsync();

            return new CachedUser
            {
                Avatar = string.Empty,
                DisplayName = user.DisplayName,
                Email = string.IsNullOrEmpty(user.Mail) ?
                    user.UserPrincipalName : user.Mail,
                AccountId = accountId
            };
        }
    }
}