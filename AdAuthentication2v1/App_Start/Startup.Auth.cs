using AdAuthentication2v1.Providers;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AdAuthentication2v1
{
    public partial class Startup
    {
        // Load configuration settings from PrivateSettings.config
        private static readonly string appId = ConfigurationManager.AppSettings["AppId"];

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
                    AuthenticationFailed = (context) =>
                    {
                        context.HandleResponse();
                        string redirect = $"/Home/Error?message={context.Exception.Message}";
                        if (context.ProtocolMessage != null && !string.IsNullOrEmpty(context.ProtocolMessage.ErrorDescription))
                        {
                            redirect += $"&debug={context.ProtocolMessage.ErrorDescription}";
                        }
                        context.Response.Redirect(redirect);
                        return Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = async (context) =>
                    {
                        try
                        {
                            var scopes = graphScopes.Split(' ');
                            var result = await ConfidentialClientApplicationProvider.GetApplicationTokensAsync(scopes, context.Code);
                            var homeAccountIdClaim = new Claim("aid", result.AccountId);

                            context.AuthenticationTicket.Identity.AddClaim(homeAccountIdClaim);

                            context.HandleCodeRedemption(result.AccessToken, result.IdToken);
                        }
                        catch (MsalException ex)
                        {
                            const string message = "AcquireTokenByAuthorizationCodeAsync threw an exception";
                            context.HandleResponse();
                            context.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
                        }
                        catch (Microsoft.Graph.ServiceException ex)
                        {
                            const string message = "GetUserDetailsAsync threw an exception";
                            context.HandleResponse();
                            context.Response.Redirect($"/Home/Error?message={message}&debug={ex.Message}");
                        }
                    }
                }
            });
        }
    }
}