using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using PhilaGov.Common.Authentication.Models;
using PhilaGov.Common.Authentication.Services.Email.Services;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace PhilaGov.Common.Authentication.Services
{

    public interface IAccountService
    {
        Task<MethodResult<string>> Login(Login model);
        Task<MethodResult<Tuple<string, IdentityUser>>> Register(Register register);
    }

    public class AccountService : IAccountService
    {

        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _accessor;
       
        public AccountService( UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,IConfiguration configuration, 
                IHttpContextAccessor accessor, IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _accessor = accessor;            
            
        }

       
        /// <summary>
        /// Validates user credentials and returns a jwt token
        /// </summary>
        /// <param name="model"></param>
        /// <returns>jwt token</returns>
        public async Task<MethodResult<string>> Login(Login model)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false);
            
            if (result.Succeeded)
            {
                var appUser = _userManager.Users.SingleOrDefault(r => r.Email == model.Email);
                var token = GenerateJwtToken(model.Email, appUser);
           
                return new MethodResult<string>() { Success = true, Data = token };
            }
            else
            {
                return new MethodResult<string>() { Success = false, Error= result.ToString() };
            }           
            
        }

        /// <summary>
        /// Registers user
        /// </summary>
        /// <param name="register"></param>
        /// <returns>jwt token</returns>
        public async Task<MethodResult<Tuple<string, IdentityUser>>> Register(Register register)
        {
            
            var user = new IdentityUser
            {
                UserName = register.Email,
                Email = register.Email
            };
            var result = await _userManager.CreateAsync(user, register.Password);

            if (result.Succeeded)
            {
                //generate email confirmation

                await _signInManager.SignInAsync(user, false);

                //SendEmailConfirmation(user);
                var jwt = GenerateJwtToken(register.Email, user);
                Tuple<string, IdentityUser> ResultVal = new Tuple<string, IdentityUser>(jwt, user);
                
                return new MethodResult<Tuple<string, IdentityUser>>() { Success = true, Data = ResultVal };
            }
            else
            {
                var errorlist = result.Errors.Select(p => p.Description).ToList();
                return new MethodResult<Tuple<string, IdentityUser>>() { Success = false, ErrorList= errorlist };
            }
            
        }
                          
        private string GenerateJwtToken(string email, IdentityUser user)
        {
            var claims = new List<Claim>
                            {
                                new Claim(JwtRegisteredClaimNames.Sub, email),
                                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                                new Claim(ClaimTypes.NameIdentifier, user.Id)
                            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration["JwtKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expires = DateTime.Now.AddDays(Convert.ToDouble(_configuration["JwtExpireDays"]));

            var token = new JwtSecurityToken(
                _configuration["JwtIssuer"],
                _configuration["JwtIssuer"],
                claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        //private async void SendEmailConfirmation(IdentityUser user)
        //{
        //    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        //    var callbackUrl = Url.Action(
        //    controller: "Account",
        //    action: "ConfirmEmail",
        //    values: new { userId = user.Id, code = code } ); // protocol: Request.Scheme

        //    await _emailService.SendEmail("Email", "Confirm your email",
        //    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

        //}

    }
}
