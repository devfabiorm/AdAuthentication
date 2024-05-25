using AdAuthentication2v1.Providers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace AdAuthentication2v1.Controllers
{
    public class HomeController : BaseController
    {
        public async Task<ActionResult> Index()
        {
            if (Request.IsAuthenticated)
            {
                var claims = ClaimsPrincipal.Current;

                var homeAccountId = claims.FindFirst(c => c.Type == "aid")?.Value;

                var account = await ConfidentialClientApplicationProvider.GetAccountAsync(homeAccountId);
            }
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public ActionResult Error(string message, string debug)
        {
            Flash(message, debug);
            return RedirectToAction("Index");
        }
    }
}