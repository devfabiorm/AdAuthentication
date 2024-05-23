using AdAuthentication.Helpers;
using AdAuthentication.TokenStorage;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace AdAuthentication
{
    public partial class Startup
    {
        // Load configuration settings from PrivateSettings.config
        private static readonly string appId = ConfigurationManager.AppSettings["AppId"];

        private static readonly string appSecret = ConfigurationManager.AppSettings["AppSecret"];

        private static readonly string graphScopes = ConfigurationManager.AppSettings["AppScopes"];

        private static readonly string redirectUri = ConfigurationManager.AppSettings["RedirectUri"];

        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or /common/ for multi-tenant)
        private static readonly string tenant = ConfigurationManager.AppSettings["Tenant"];
        // Authority is the URL for authority, composed by Microsoft identity platform endpoint and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
        private readonly string authority = string.Format(System.Globalization.CultureInfo.InvariantCulture, ConfigurationManager.AppSettings["Authority"], tenant);

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = appId,
                    Authority = authority,
                    Scope = $"openid {graphScopes}",
                    RedirectUri = redirectUri,
                    PostLogoutRedirectUri = redirectUri,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = OnAuthenticationFailedAsync,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceivedAsync
                    }
                }
            );
        }

        private static Task OnAuthenticationFailedAsync(AuthenticationFailedNotification<OpenIdConnectMessage,
            OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();
            string redirect = $"/Home/Error?message={notification.Exception.Message}";
            if (notification.ProtocolMessage != null && !string.IsNullOrEmpty(notification.ProtocolMessage.ErrorDescription))
            {
                redirect += $"&debug={notification.ProtocolMessage.ErrorDescription}";
            }
            notification.Response.Redirect(redirect);
            return Task.FromResult(0);
        }

        private async Task OnAuthorizationCodeReceivedAsync(AuthorizationCodeReceivedNotification notification)
        {
            var idClient = ConfidentialClientApplicationBuilder.Create(appId)
                .WithRedirectUri(redirectUri)
                .WithClientSecret(appSecret)
                .WithAuthority(authority)
                .Build();

            var tokenStore = new SessionTokenCustomCache(idClient.UserTokenCache, HttpContext.Current);

            try
            {
                string[] scopes = graphScopes.Split(' ');

                var result = await idClient.AcquireTokenByAuthorizationCode(
                    scopes, notification.Code).ExecuteAsync();



                var idToken = new JwtSecurityToken(result.IdToken);

                //Populating authentication context with data got from token
                var accountIdClaim = new Claim("aid", tokenStore.UserUniqueIdentifier);
                var appRoles = idToken.Claims.Where(c => c.Type.Equals(ClaimTypes.Role)).ToList();
                var claimsList = new List<Claim> { accountIdClaim }.Concat(appRoles).ToList();
                notification.AuthenticationTicket.Identity.AddClaims(claimsList);

                var userDetails = await GraphHelper.GetUserDetailsAsync(result.AccessToken, tokenStore.UserUniqueIdentifier);

                tokenStore.SaveUserDetails(userDetails);
                notification.HandleCodeRedemption(null, result.IdToken);
            }
            catch (MsalException ex)
            {
                const string message = "AcquireTokenByAuthenticationCodeAsync threw an exception";
                notification.HandleResponse();
                notification.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
            }
            catch (Microsoft.Graph.ServiceException ex)
            {
                const string message = "GetUserDetailsAsync threw an exception";
                notification.HandleResponse();
                notification.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
            }
        }
    }
}