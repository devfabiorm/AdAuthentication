﻿using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Web;
using System.Web.Mvc;

namespace Authenticationv3.Controllers
{
    public class AccountController : Controller
    {
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {
                // Signal OWIN to send an authorization request to Azure
                Request.GetOwinContext().Authentication.Challenge(
                    new AuthenticationProperties { RedirectUri = "/" },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        public ActionResult SignOut()
        {
            if (Request.IsAuthenticated)
            {
                Request.GetOwinContext().Authentication.SignOut(
                    CookieAuthenticationDefaults.AuthenticationType);
            }

            return RedirectToAction("Index", "Home");
        }
    }
}