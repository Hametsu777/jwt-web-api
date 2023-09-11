using System.Security.Claims;

namespace JwtWebApi.Services
{
    // Need to inject IHttpContextAccessor to be able to access claims.
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpcontextAccessor;

        public UserService(IHttpContextAccessor httpcontextAccessor)
        {
            _httpcontextAccessor = httpcontextAccessor;
        }

        public string GetMyName()
        {
            var result = string.Empty;
            if (_httpcontextAccessor.HttpContext is not null)
            {
                result = _httpcontextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }

            return result;
        }
    }
}
