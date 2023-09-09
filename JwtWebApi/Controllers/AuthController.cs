﻿using JwtWebApi.DTOs;
using JwtWebApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        // Iconfiguration grants access to appsettings.json.
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("/register")]
        public ActionResult<User> Register(UserDto request)
        {
            // Hashing password.
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }

        [HttpPost("/login")]
        public ActionResult<User> Login(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("User not found!");
            }

            // Verify if requested password matches user password.
            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return BadRequest("Password does not exist.");
            }
            string token = CreateToken(user);
            return Ok(token);
        }

        // Creating a Json webtoken manually. Need user object to set the username as a claim to the token.
        // Key is wrapped from app settings. Credentials are needed with the key. Token is then needed.
        // Token is then writen with JwtSecurtiyTokenHandler and json web token is returned.
        private string CreateToken(User user)
        {
            // Need to learn more about claims in depth.
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.Username)
            };

            // When using SymmetricSecurityKey, need to install IdentityModel.Tokens.
            // Key is used to create Json web token and verify Json web token.
            // Need to learn more about SymmetricSecurityKey in depth.
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value!));

            // need sign in credentials. Have to put key and algorithm used for the json web token.
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            // Generate token. Need to install IdentityModel.Tokens.Jwt.
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            // Write token
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}