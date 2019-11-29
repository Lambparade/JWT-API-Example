using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace API_JWT_Test.Controllers
{
	[Route("api/[controller]")]
	public class AuthController : Controller
	{
		// GET: api/<controller>
		private readonly IConfiguration _config;

		public AuthController(IConfiguration config)
		{
			_config = config;
		}

		[AllowAnonymous]
		[HttpPost]
		public IActionResult CreateToken([FromBody]LoginModel login)
		{
			if (login == null) return Unauthorized();
			string tokenString = string.Empty;
			bool validUser = Authenticate(login);
			if (validUser)
			{
				tokenString = BuildToken();
			}
			else
			{
				return Unauthorized();
			}
			return Ok(new { Token = tokenString });
			
		}

		[HttpGet("[action]")]
		[Authorize]
		public string CheckAuth()
		{
			return "You have been Authenticated!";
		}

		private string BuildToken()
		{
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtToken:SecretKey"]));
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			var token = new JwtSecurityToken(_config["JwtToken:Issuer"],
				_config["JwtToken:Issuer"],
				expires: DateTime.Now.AddMinutes(30),
				signingCredentials: creds);

			return new JwtSecurityTokenHandler().WriteToken(token);
		}

		private bool Authenticate(LoginModel login)
		{
			bool validUser = false;

			if (login.Username == "SampleUser"  && login.Password == "SamplePassword")
			{
				validUser = true;
			}
			return validUser;
		}

		public class LoginModel
		{
			public string Username { get; set; }
			public string Password { get; set; }
		}

	}
}
