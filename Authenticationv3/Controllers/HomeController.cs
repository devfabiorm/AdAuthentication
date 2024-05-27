using Authenticationv3.Helpers;
using Authenticationv3.Providers;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace Authenticationv3.Controllers
{
    public class HomeController : BaseController
    {
        public async Task<ActionResult> Index()
        {
            if (Request.IsAuthenticated)
            {
                

                ViewBag.User = await GraphHelper.GetUserDetailsAsync();
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