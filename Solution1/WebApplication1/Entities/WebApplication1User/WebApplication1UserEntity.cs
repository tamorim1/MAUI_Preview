using Microsoft.AspNetCore.Identity;
using System;

namespace WebApplication1.Entities.WebApplication1User
{
    public class WebApplication1UserEntity : IdentityUser<Guid>
    {
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
    }
}
