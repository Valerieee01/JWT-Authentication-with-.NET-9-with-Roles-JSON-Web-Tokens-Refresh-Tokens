using JwtAuthDotNet9.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using JwtAuthDotNet9.Entities;
using System.Security.Claims;
using System.Security.Cryptography;


namespace JwtAuthDotNet9.Controllers
{
    [Route("api/[controller]")]
    [ApiController] 
    public class AuthController : ControllerBase
    {

        public static User user = new();

        [HttpPost("register")]
        public ActionResult<User> Register(UserDTOs request)
        {
            var hashesdPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);

            user.Username = request.Username;
            user.PasswordHash = hashesdPassword;

            return Ok(user);
        }

        [HttpPost("login")]
        public ActionResult<String> Login(UserDTOs request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not Found");
            }

            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) 
                == PasswordVerificationResult.Failed)
            {
                return BadRequest("Wrong Password.");
            }

            string token = "suscces";

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key  = new SymmetricSecurityKey()
        }
    }
}
