using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(Authenticationv3.Startup))]

namespace Authenticationv3
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}