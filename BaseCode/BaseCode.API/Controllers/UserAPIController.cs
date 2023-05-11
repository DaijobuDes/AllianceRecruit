using BaseCode.API.Authentication;
using BaseCode.API.Utilities;
using BaseCode.Data;
using BaseCode.Data.ViewModels;
using BaseCode.Domain.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Security.Claims;
using BaseCode.Data.Models;
using System.Linq;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace BaseCode.API.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class UserAPIController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserAPIController(IUserService userService)
        {
            _userService = userService;
        }

        [AllowAnonymous]
        [HttpPost]
        [ActionName("register")]
        public async Task<HttpResponseMessage> PostRegister(UserViewModel userModel)
        {
            if (userModel.Password != userModel.ConfirmPassword)
            {
                return Helper.ComposeResponse(HttpStatusCode.BadRequest, "The password and confirmation password do not match.");
            }

            if (!userModel.RoleName.Equals(Constants.Roles.Admin) && !userModel.RoleName.Equals(Constants.Roles.User))
            {
                return Helper.ComposeResponse(HttpStatusCode.BadRequest, "Invalid role.");
            }

            if (!ModelState.IsValid)
            {
                return Helper.ComposeResponse(HttpStatusCode.BadRequest, Helper.GetModelStateErrors(ModelState));
            }

            var result = await _userService.RegisterUser(userModel.UserName, userModel.Password, userModel.FirstName, userModel.LastName, userModel.EmailAddress, userModel.RoleName);
            var errorResult = GetErrorResult(result);

            return errorResult ? Helper.ComposeResponse(HttpStatusCode.BadRequest, ModelState) : Helper.ComposeResponse(HttpStatusCode.OK, "Successfully added user");
        }

        [AllowAnonymous]
        [HttpPost]
        [ActionName("roles")]
        [Authorize(Roles = "Administrator")]
        public async Task<HttpResponseMessage> PostCreateRole(string role)
        {
            if (string.IsNullOrEmpty(role))
            {
                return Helper.ComposeResponse(HttpStatusCode.BadRequest, Constants.Common.InvalidRole);
            }

            var result = await _userService.CreateRole(role);
            var errorResult = GetErrorResult(result);

            return errorResult ? Helper.ComposeResponse(HttpStatusCode.BadRequest, Constants.Common.InvalidRole) : Helper.ComposeResponse(HttpStatusCode.OK, "Successfully added role");
        }

        [AllowAnonymous]
        [HttpPost]
        [ActionName("login")]
        public async Task<object> PostLogin(string username, string password)
        {
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return Helper.ComposeResponse(HttpStatusCode.BadRequest, Constants.User.Empty);
            }

            var result = await _userService.FindUserAsync(username, password);

            if (result == null)
            {
                return Helper.ComposeResponse(HttpStatusCode.BadRequest, Constants.User.InvalidUserNamePassword);
            }

            var token = GenerateJwtToken(result.Username, result.RoleName);
            return Ok(token);

        }

         [HttpGet]
         [ActionName("test")]
         [Authorize(Roles = "Administrator")]
         public IActionResult GetTest()
         {
            var currentUser = GetCurrentUser();
            return Ok($"Hello {currentUser.UserName}! You are have the role of {currentUser.RoleName}.");
         }

        private string GenerateJwtToken(string username, string role)
        {
            // Token handling
            // Encoding.ASCII.GetBytes(Configuration.Config.GetSection("BaseCode:AuthSecretKey").Value)
            // SHA256: E79CA2B27F87CAA73D0A55C9F5F59C97036C51571F4F36D9617AE965FBE53357

            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.Config.GetSection("BaseCode:AuthSecretKey").Value));
            // var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("E79CA2B27F87CAA73D0A55C9F5F59C97036C51571F4F36D9617AE965FBE53357"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                // new Claim("username", username),
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.Role, role),
            };

            var issuer = Configuration.Config.GetSection("BaseCode:Issuer").Value;
            var audience = Configuration.Config.GetSection("BaseCode:Audience").Value;

            var token = new JwtSecurityToken(issuer, audience, claims, expires: DateTime.UtcNow.AddMinutes(30), signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserViewModel GetCurrentUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            if (identity == null) 
            {
                return null;
            }
            var userClaims = identity.Claims;

            return new UserViewModel
            {
                UserName = userClaims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value,
                RoleName = userClaims.FirstOrDefault(x => x.Type == ClaimTypes.Role)?.Value
            };
        }

        private bool GetErrorResult(IdentityResult result)
        {
            if (result.Succeeded || result.Errors == null) return false;

            var flag = false;
            foreach (var error in result.Errors)
            {
                flag = true;
                ModelState.AddModelError("ModelStateErrors", error.Description);
            }

            return flag;
        }
    }
}