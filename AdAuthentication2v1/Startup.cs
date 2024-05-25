using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(AdAuthentication2v1.Startup))]

namespace AdAuthentication2v1
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
