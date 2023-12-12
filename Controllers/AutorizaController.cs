using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using apiUniversidade.Context;
using apiUniversidade.Model;
using ApiUniversidade2.DTO;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace ApiUniversidade2.Controllers
{
    [ApiController]
    [Route("[controller]")] 
    public class AutorizaController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AutorizaController(UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
            public ActionResult<string> Get(){
                return "AutorizaController :: Acessado em : "
                    + DateTime.Now.ToLongDateString();
            }
        [HttpPost("register")]
            public async Task<ActionResult> RegisterUser([FromBody]UsuarioDTO model){
                var user = new IdentityUser{
                    UserName = model.Email,
                    Email = model.Email,
                    EmailConfirmed = true
                };

            var result = await _userManager.CreateAsync(user, model.Password);
            if(!result.Succeeded)
                return BadRequest(result.Errors);

            await _signInManager.SignInAsync(user, false);
            //return OK(GerarToken(model));
            return Ok(GerarToken(model));
            }
        [HttpPost("login")]
            public async Task<ActionResult> Login([FromBody] UsuarioDTO userInfo){

                var result = await _signInManager.PasswordSignInAsync(userInfo.Email, userInfo.Password,
                    isPersistent: false, lockoutOnFailure: false );

                if(!result.Succeeded)
                    return Ok();
                else{
                    ModelState.AddModelError(string.Empty, "Login Invalido...");
                    return BadRequest(ModelState);

                }

            }
        private readonly IConfiguration _configuration;

            public AutorizaController(UserManager<IdentityUser> userManager,
                    SignInManager<IdentityUser> signInManager, IConfiguration configuration)
            {
                _userManager = userManager;
                _signInManager = signInManager;
                _configuration = configuration;
            }
        
        private UsuarioToken GerarToken(UsuarioDTO userInfo){

            var claims = new[]{
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.UniqueName,userInfo.Email),
                new Claim("IFRN", "TecInfo"),
                new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
            };
            
            //gerar chaver através de um algoritmo de chave simétrica
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["Jwt:key"]));

            //gerar a assinatura digital do token utilizando
            //a chave privada (key) e o algoritmo HMAC SHA 256
            var credentials = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

            //tempo de expiracao do token
            var expiracao =_configuration["TokenConfiguration:ExpireHours"];
            var expiration = DateTime.UtcNow.AddHours(double.Parse(expiracao));

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: _configuration["TokenConfiguration:Issuer"],
                audience: _configuration["TokenConfiguration:Audience"],
                claims: claims,
                expires: expiration,
                signingCredentials: credentials
            );

            return new UsuarioToken(){
                Authenticated = true,
                Expiration = expiration,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Message = "JWT OK."

            };
        }
    }
}   