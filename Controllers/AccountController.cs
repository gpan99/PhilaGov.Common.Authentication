using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using PhilaGov.Common.Authentication.Models;
using PhilaGov.Common.Authentication.Services;
using PhilaGov.Common.Authentication.Services.Email.Services;

namespace PhilaGov.Common.Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _accountService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailService _emailService;

        public AccountController(IAccountService accountService, UserManager<IdentityUser> userManager, IEmailService emailService)
        {
            _accountService = accountService;
            _userManager = userManager;
            _emailService = emailService;
        }

        [HttpPost, Route("Login")]
        public IActionResult Login([FromBody] Login model)
        {
            var methodResult = _accountService.Login(model).Result;


            if (methodResult.Success)
            {
                return Ok(methodResult?.Data);
            }

            //var res = methodResult?.ErrorList ?? new List<string>() ;

            return NotFound(methodResult.Error);
        }

        /// <summary>
        /// Register the user with provided email address.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost, Route("Register")]
        public IActionResult Register([FromBody] Register model)
        {

            var methodResult = _accountService.Register(model).Result;

            if (methodResult.Success)
            {
                Tuple<string, IdentityUser> temp = methodResult.Data;
                SendEmailConfirmation(temp.Item2);
                return Ok(temp.Item1);
            }

            return NotFound(methodResult.ErrorList);
        }

        /// <summary>
        /// Send  confirmation email to the user for activation
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="code"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId = "", string code = "")
        {
            if (userId?.Length == 0 || code?.Length == 0)
                return NotFound();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new ApplicationException($"Unable to load user with ID '{userId}'.");

            var result = await this._userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
                return Ok("user email is confirmed");
            else
                return StatusCode(500);
        }
        [HttpGet]
        [Route("SendPasswordEmail0")]
        public async Task<IActionResult> SendPasswordEmail0(string useremail)
        {
            try
            {
                if (useremail?.Length == 0)
                    return NotFound();

                var user = await _userManager.FindByEmailAsync(useremail);

                if (user == null)
                    throw new ApplicationException($"Unable to find email");

                var token = _userManager.GeneratePasswordResetTokenAsync(user).Result;

                var password = GenerateRandomPassword();

                var t = await _userManager.ResetPasswordAsync(user, token, password);

                SendPasswordEmailConfirmation(user, password);

                return Ok("check your email : " + user.UserName);
            }
            catch
            {
                return StatusCode(500);
            }
        }
        [HttpGet]
        [Route("SendFilerIdEmail")]
        public async Task<IActionResult> SendFilerIdEmail(string useremail)
        {
            try
            {
                if (useremail?.Length == 0)
                    return NotFound();

                var user = await _userManager.FindByEmailAsync(useremail);
                if (user.EmailConfirmed)
                {
                    return Ok("Your filerId : " + user.UserName);
                }
                if (user == null)
                    throw new ApplicationException($"Unable to find user");

                SendEmailConfirmation(user);
                return Ok();
            }
            catch
            {
                return StatusCode(500);
            }

        }
        /// <summary>
        /// Generates a Random Password
        /// respecting the given strength requirements.
        /// </summary>
        /// <param name="opts">A valid PasswordOptions object
        /// containing the password strength requirements.</param>
        /// <returns>A random password</returns>
        public static string GenerateRandomPassword(PasswordOptions opts = null)
        {
            if (opts == null) opts = new PasswordOptions()
            {
                RequiredLength = 6,
                RequiredUniqueChars = 4,
                RequireDigit = true,
                RequireLowercase = true,
                RequireNonAlphanumeric = true,
                RequireUppercase = true
            };

            string[] randomChars = new[] {
        "ABCDEFGHJKLMNOPQRSTUVWXYZ",    // uppercase 
        "abcdefghijkmnopqrstuvwxyz",    // lowercase
        "0123456789",                   // digits
        "!@$?_-"                        // non-alphanumeric
    };
            Random rand = new Random(Environment.TickCount);
            List<char> chars = new List<char>();

            if (opts.RequireUppercase)
                chars.Insert(rand.Next(0, chars.Count),
                    randomChars[0][rand.Next(0, randomChars[0].Length)]);

            if (opts.RequireLowercase)
                chars.Insert(rand.Next(0, chars.Count),
                    randomChars[1][rand.Next(0, randomChars[1].Length)]);

            if (opts.RequireDigit)
                chars.Insert(rand.Next(0, chars.Count),
                    randomChars[2][rand.Next(0, randomChars[2].Length)]);

            if (opts.RequireNonAlphanumeric)
                chars.Insert(rand.Next(0, chars.Count),
                    randomChars[3][rand.Next(0, randomChars[3].Length)]);

            for (int i = chars.Count; i < opts.RequiredLength
                || chars.Distinct().Count() < opts.RequiredUniqueChars; i++)
            {
                string rcs = randomChars[rand.Next(0, randomChars.Length)];
                chars.Insert(rand.Next(0, chars.Count),
                    rcs[rand.Next(0, rcs.Length)]);
            }

            return new string(chars.ToArray());
        }

        /// <summary>
        /// Resend confirmation email
        /// </summary>
        /// <param name="useremail"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("ResendConfirmEmail")]
        public async Task<IActionResult> ResendConfirmEmail(string useremail)
        {
            try
            {
                if (useremail?.Length == 0)
                    return NotFound();
                //return Unauthorized();

                var user = await _userManager.FindByEmailAsync(useremail);
                if (user.EmailConfirmed)
                {
                    return Ok("Your email is already confirmed"); // send a message to inform user that  he is already confirmed.
                }
                if (user == null)
                    throw new ApplicationException($"Unable to find user");

                SendEmailConfirmation(user);
                return Ok();
            }
            catch
            {
                return StatusCode(500);
            }
        }

        private async void SendPasswordEmailConfirmation(IdentityUser user, string password)
        {

            //var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            //var callbackUrl = Url.Action(
            //controller: "Account",
            //action: "ConfirmEmail",
            //values: new { userId = user.Id, code = code },
            //protocol: Request.Scheme);

            await _emailService.SendEmail(user.Email, "Your password", password);
        }
        private async void SendEmailConfirmation(IdentityUser user)
        {

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = Url.Action(
            controller: "Account",
            action: "ConfirmEmail",
            values: new { userId = user.Id, code = code },
            protocol: Request.Scheme);
            var msg = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.";
            msg = msg.Replace("&amp;", "&");
            //     var html = Regex.Replace(msg, "&(?!(?<=(?<outerquote>[\"'])javascript:(?>(?!\\k<outerquote>|[>]).)*)\\k<outerquote>?)(?!(?:[a-zA-Z][a-zA-Z0-9]*|#\\d+);)(?!(?>(?:(?!<script|\\/script>).)*)\\/script>)", "&amp;", RegexOptions.Singleline | RegexOptions.IgnoreCase);
            await _emailService.SendEmail(user.Email, "Confirm your email", msg);
        }
        [HttpGet("SendPasswordEmail", Name = nameof(SendPasswordEmail))]
        public async Task<IActionResult> SendPasswordEmail(string useremail)
        {
            try
            {
                //var user = _userService.GetUser(useremail);
                var user = await _userManager.FindByEmailAsync(useremail);

                if (user == null)
                    return Ok("Unable to find email");
                var newpassword = GenerateRandomPassword();
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action(
                controller: "Account", //action: "ConfirmEmail",
                action: "ResetPassword",
                values: new { userId = user.Id, code = code , newPassword = newpassword},
                protocol: Request.Scheme);

                var msg = $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.";
                msg = msg.Replace("&amp;", "&");
                await _emailService.SendEmail(useremail, "Reset password", msg);

                return Ok("Your reset password link is sent to your email");
            }
            catch (Exception ex)
            {
                return StatusCode(500);
            }
        }
        
        [HttpGet]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword(string userId = "", string code = "",string newPassword="")
        {
            if (userId?.Length == 0 || code?.Length == 0)
                return NotFound();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new ApplicationException($"Unable to load user with ID '{userId}'.");

            var result = await this._userManager.ResetPasswordAsync(user, code, newPassword);

            await _emailService.SendEmail(user.Email, "Your password is ", newPassword);

            if (result.Succeeded)
                return Ok(code);
            else
                return StatusCode(500);
        }
    }
}