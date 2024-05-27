using Authenticationv3.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.TokenCacheProviders.Distributed;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace Authenticationv3.Providers
{
    public static class AuthenticationProvider
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
        private static Lazy<IConfidentialClientApplication> lazyClientApp = new Lazy<IConfidentialClientApplication>(() =>
        {

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

        public static async Task<AuthenticationInformation> GetApplicationTokensAsync(IEnumerable<string> scopes, string applicationCode = null, IAccount account = null)
        {
            var result = await AuthenticateAsync(scopes, applicationCode, account);

            return new AuthenticationInformation
            {
                AccessToken = result.AccessToken,
                AccountId = result.Account.HomeAccountId.Identifier,
                IdToken = result.IdToken,
            };
        }

        public static Task<IAccount> GetAccountAsync(string accountId)
        {
            var app = lazyClientApp.Value;

            return app.GetAccountAsync(accountId);
        }

        private static async Task<AuthenticationResult> AuthenticateAsync(IEnumerable<string> scopes, string code = null, IAccount account = null)
        {
            var app = lazyClientApp.Value;

            try
            {
                if (account == null && !string.IsNullOrEmpty(code))
                {
                    //This method does not look in the token cache, but stores the result in it.  (refer to https://learn.microsoft.com/en-us/dotnet/api/microsoft.identity.client.iconfidentialclientapplication?view=msal-dotnet-latest)
                    return await app.AcquireTokenByAuthorizationCode(scopes, code)
                        .ExecuteAsync();
                }

                //This method does look in the token cache before calling Azure. (refer to https://learn.microsoft.com/en-us/dotnet/api/microsoft.identity.client.iconfidentialclientapplication?view=msal-dotnet-latest)
                return await app.AcquireTokenSilent(scopes, account)
                                  .ExecuteAsync();
            }
            catch (MsalUiRequiredException ex)
            {
                // A MsalUiRequiredException happened on AcquireTokenSilent.
                // This indicates you need to call AcquireTokenInteractive to acquire a token
                Debug.WriteLine($"MsalUiRequiredException: {ex.Message}");

                try
                {
                    return await app.AcquireTokenForClient(scopes)
                                      .ExecuteAsync();
                }
                catch (MsalException msalex)
                {
                    Debug.WriteLine($"Error Acquiring Token:{Environment.NewLine}{msalex}");
                    throw;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error Acquiring Token Silently:{Environment.NewLine}{ex}");
                throw;
            }
        }
    }
}