using JwtAuthDotNet9.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using JwtAuthDotNet9.Entities;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using JwtAuthDotNet9.Services;
using Microsoft.AspNetCore.Authorization;


namespace JwtAuthDotNet9.Controllers
{
    [Route("api/[controller]")]
    [ApiController] 
    public class AuthController(IAuthService authService) : ControllerBase
    {

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTOs request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null)
            {
                return BadRequest("Usuario ya existe");
            }
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<String>> Login(UserDTOs request)
        {
           var token = await authService.LoginAsync(request);
            if (token is null)
            {
                return BadRequest("Credenciales invalidas");
            }
            return Ok(token);
        }

        [Authorize]
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint()
        {
            return Ok("Estas autenticado");
        }

       
    }
}
