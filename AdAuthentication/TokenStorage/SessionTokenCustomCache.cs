using AdAuthentication.Models;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Threading;
using System.Web;

namespace AdAuthentication.TokenStorage
{
    public class SessionTokenCustomCache
    {
        private static readonly ReaderWriterLockSlim sessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

        private HttpContext httpContext;

        private string rawKey;
        private string tokenCacheKey;
        private string userCacheKey;

        public string UserUniqueIdentifier
        {
            get => rawKey;
            set
            {
                rawKey = value;
                tokenCacheKey = $"{value}_tokenKey";
                userCacheKey = $"{value}_userKey";
            }
        }

        public SessionTokenCustomCache(ITokenCache tokenCache, HttpContext context)
        {
            httpContext = context;

            if (tokenCache != null)
            {
                tokenCache.SetBeforeAccess(BeforeAccessNotification);
                tokenCache.SetAfterAccess(AfterAccessNotification);
            }
        }

        public void Clear()
        {
            sessionLock.EnterWriteLock();

            try
            {
                httpContext.Session.Remove(tokenCacheKey);
            }
            finally
            {
                sessionLock.ExitWriteLock();
            }
        }

        public CachedUser GetUserDetails()
        {
            sessionLock.EnterReadLock();
            var cachedUser = JsonConvert.DeserializeObject<CachedUser>((string)httpContext.Session[userCacheKey]);
            sessionLock.ExitReadLock();
            return cachedUser;
        }

        public string GetUsersUniqueId(ClaimsPrincipal claims)
        {
            if (string.IsNullOrEmpty(UserUniqueIdentifier) && claims != null)
            {
                return claims.FindFirst("aid")?.Value;
            }

            return UserUniqueIdentifier;
        }

        public bool HasData(ClaimsPrincipal claims)
        {
            if (string.IsNullOrEmpty(UserUniqueIdentifier))
                UserUniqueIdentifier = GetUsersUniqueId(claims);

            return httpContext.Session[tokenCacheKey] != null && ((byte[])httpContext.Session[tokenCacheKey]).Length > 0;
        }

        public void SaveUserDetails(CachedUser user)
        {
            sessionLock.EnterWriteLock();
            httpContext.Session[userCacheKey] = JsonConvert.SerializeObject(user);
            sessionLock.ExitWriteLock();
        }

        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            if (args.HasStateChanged)
            {
                sessionLock.EnterWriteLock();

                try
                {
                    httpContext.Session[tokenCacheKey] = args.TokenCache.SerializeMsalV3();
                }
                finally
                {
                    sessionLock.ExitWriteLock();
                }
            }
        }

        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            UserUniqueIdentifier = args.SuggestedCacheKey;

            sessionLock.EnterReadLock();
            try
            {
                args.TokenCache.DeserializeMsalV3((byte[])httpContext.Session[tokenCacheKey]);
            }
            finally
            {
                sessionLock.ExitReadLock();
            }
        }
    }
}