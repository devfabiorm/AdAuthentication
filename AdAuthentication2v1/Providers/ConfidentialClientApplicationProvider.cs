using AdAuthentication2v1.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.TokenCacheProviders.Distributed;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace AdAuthentication2v1.Providers
{
    public static class ConfidentialClientApplicationProvider
    {
        private const string Oid = "oid";
        private const string Tid = "tid";
        private const string ObjectId = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        private const string TenantId = "http://schemas.microsoft.com/identity/claims/tenantid";

        // Load configuration settings from PrivateSettings.config
        private static readonly string clienteId = ConfigurationManager.AppSettings["AppId"];
        private static readonly string clientSecret = ConfigurationManager.AppSettings["AppSecret"];
        private static readonly string redirectUri = ConfigurationManager.AppSettings["RedirectUri"];

        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or /common/ for multi-tenant)
        private static readonly string tenant = ConfigurationManager.AppSettings["Tenant"];
        // Authority is the URL for authority, composed by Microsoft identity platform endpoint and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
        private static readonly string authority = string.Format(System.Globalization.CultureInfo.InvariantCulture, ConfigurationManager.AppSettings["Authority"], tenant);

        // We keep global client app
        private static Lazy<IConfidentialClientApplication> lazyClientApp = new Lazy<IConfidentialClientApplication>(() => {

            var app = ConfidentialClientApplicationBuilder
                .Create(clienteId)
                .WithClientSecret(clientSecret)
                .WithRedirectUri(redirectUri)
                .WithAuthority(authority)
                .Build();

            // After the ConfidentialClientApplication is created, we overwrite its default UserTokenCache serialization with our implementation
            // Redis token cache
            app.AddDistributedTokenCache(services =>
            {
                // Requires to reference Microsoft.Extensions.Caching.StackExchangeRedis
                services.AddStackExchangeRedisCache(options =>
                {
                    options.Configuration = "localhost";
                    options.InstanceName = "Redis";
                });

                // You can even decide if you want to repair the connection
                // with Redis and retry on Redis failures. 
                services.Configure<MsalDistributedTokenCacheAdapterOptions>(options =>
                {
                    options.OnL2CacheFailure = (ex) =>
                    {
                        if (ex is StackExchange.Redis.RedisConnectionException)
                        {
                            // action: try to reconnect or something
                            return true; //try to do the cache operation again
                        }
                        return false;
                    };
                });
            });

            return app;
        },
            true);

        public static async Task<AuthenticationInformation> GetApplicationTokensAsync(IEnumerable<string> scopes, string applicationCode)
        {
            var app = lazyClientApp.Value;

            var result = await app.AcquireTokenByAuthorizationCode(
                    scopes, applicationCode).ExecuteAsync();



            return new AuthenticationInformation
            {
                AccessToken = result.AccessToken,
                AccountId = result.Account.HomeAccountId.Identifier,
                IdToken = result.IdToken,
            };
        }

        public static async Task<IAccount> GetAccountAsync(string accountId)
        {
            var app = lazyClientApp.Value;

            var test = await app.GetAccountAsync(accountId);

            return test;
        }
    }
}