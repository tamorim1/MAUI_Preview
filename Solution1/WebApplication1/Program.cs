using Microsoft.AspNetCore.Builder;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using WebApplication1.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using WebApplication1.Entities.WebApplication1User;
using WebApplication1.Entities.WebApplication1Role;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication;
using System.Security.Cryptography;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Data.SqlClient;

public class Program
{
    public static async Task Main(string[] args)
    {
        
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddDbContext<WebApplication1DbContext>(o =>
        {
            var connectionString = new SqlConnectionStringBuilder();

            connectionString.DataSource = builder.Configuration["DataSource"] ?? builder.Configuration["ConnectionString:DataSource"];
            connectionString.InitialCatalog = builder.Configuration["InitialCatalog"] ?? builder.Configuration["ConnectionString:InitialCatalog"];
            connectionString.PersistSecurityInfo = true;
#if DEBUG
            connectionString.TrustServerCertificate = true;
#endif
            connectionString.UserID = builder.Configuration["UserID"] ?? builder.Configuration["ConnectionString:UserID"];
            connectionString.Password = builder.Configuration["Password"] ?? builder.Configuration["ConnectionString:Password"];
            connectionString.MultipleActiveResultSets = true;
            connectionString.CurrentLanguage = "Portuguese";

            o.UseSqlServer(connectionString.ToString());
            o.EnableDetailedErrors();
            o.EnableSensitiveDataLogging();
        });

        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(s =>
        {
            s.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
            {
                Name = "Authorization",
                Type = SecuritySchemeType.Http,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "JWT Authorization header using the Bearer scheme."
            });

            s.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] {}
                }
            });
        });

        builder.Services.AddIdentity<WebApplication1UserEntity, WebApplication1RoleEntity>(o =>
        {
            o.SignIn.RequireConfirmedAccount = false;

        }).AddEntityFrameworkStores<WebApplication1DbContext>().AddDefaultTokenProviders();

        builder.Services.AddAuthentication(o =>
        {
            o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(o =>
        {
            o.SaveToken = true;
            o.RequireHttpsMetadata = false;
            o.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.Zero,
                ValidAudience = builder.Configuration["JWT:ValidAudience"],
                ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
            };
        });

        builder.Services.AddAuthorization();

        builder.Services.AddSignalR(c =>
        {
            c.EnableDetailedErrors = true;
        });

        //builder.Services.AddCors();

        var app = builder.Build();

        app.UseSwagger();
        app.UseSwaggerUI();


        //app.UseHttpsRedirection();
        app.UseHttpLogging();

        app.UseAuthentication();
        app.UseAuthorization();

        #region Register
        app.MapPost("auth/register", async ([FromServices] UserManager<WebApplication1UserEntity> userManager,
                                            [FromBody] RegisterDTO registerDTO,
                                            CancellationToken cancellationToken) =>
        {

            var userExists = await userManager.FindByNameAsync(registerDTO.Usuario);

            if(userExists != null)
            {
                return Results.BadRequest(new AuthenticationResponseDTO() 
                { 
                    Result = false,
                    Errors = new List<object>() { "Usuário já cadastrado." }
                });
            }

            var newUser = new WebApplication1UserEntity()
            {
                UserName = registerDTO.Usuario,
                Email = registerDTO.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await userManager.CreateAsync(newUser, registerDTO.Senha);

            if (!result.Succeeded)
            {
                return Results.BadRequest(new AuthenticationResponseDTO()
                {
                    Result = false,
                    Errors = result.Errors.ToList<object>()
                });
            }

            return Results.Ok(new AuthenticationResponseDTO()
            {
                Result = true,

            });

        });

        #endregion

        #region Login
        app.MapPost("auth/login", async ([FromServices] UserManager<WebApplication1UserEntity> userManager,
                                         [FromServices] SignInManager<WebApplication1UserEntity> signInManager,
                                         [FromBody] LoginDTO loginDTO,
                                          CancellationToken cancellationToken) =>
        {
            var userExists = await userManager.FindByNameAsync(loginDTO.Usuario);


            if (userExists == null || !(await signInManager.CheckPasswordSignInAsync(userExists,loginDTO.Senha,false)).Succeeded)
            {
                return Results.BadRequest(new AuthenticationResponseDTO()
                {
                    Result = false,
                    Errors = new List<object>() { "Usuário e/ou senha inválido." }
                });
            }

            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, loginDTO.Usuario),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };
            
            if(userExists.UserName == "ADM")
            {
                authClaims.Add(new Claim(ClaimTypes.Role, "EMPRESAS:CONSULTAR"));
                authClaims.Add(new Claim(ClaimTypes.Role, "EMPRESAS:INCLUIR"));
                authClaims.Add(new Claim(ClaimTypes.Role, "EMPRESAS:ALTERAR"));
                authClaims.Add(new Claim(ClaimTypes.Role, "EMPRESAS:EXCLUIR"));
            }

            var token = new JwtSecurityTokenHandler().WriteToken(GenerateToken(authClaims, builder.Configuration));
            var refreshToken = GenerateRefreshToken();

            userExists.RefreshToken = refreshToken;
            var parsed = int.TryParse(builder.Configuration["JWT:RefreshTokenValidityInHours"], out int refreshTokenValidityInHours);
            userExists.RefreshTokenExpiryTime = DateTime.Now.AddHours(parsed ? refreshTokenValidityInHours : 1);

            await userManager.UpdateAsync(userExists);

            return Results.Ok(new AuthenticationResponseDTO()
            {
                Result = true,
                Token = token,
                RefreshToken = refreshToken
            });


        });

        #endregion

        #region Refresh
        app.MapPost("auth/refresh", async ([FromServices] UserManager<WebApplication1UserEntity> userManager,
                                          [FromBody] RefreshDTO refreshDTO,
                                          CancellationToken cancellationToken) =>
        {


            if (refreshDTO == null)
            {
                return Results.BadRequest(new AuthenticationResponseDTO()
                {
                    Result = false,
                    Errors = new List<object>() { "Requisição inválida." }
                });
            }

            var principal = GetPrincipalFromExpiredToken(refreshDTO.Token, builder.Configuration);
     
            var userExists = await userManager.FindByNameAsync(principal!.Identity!.Name);


            if (userExists == null || userExists.RefreshToken != refreshDTO.RefreshToken || userExists.RefreshTokenExpiryTime <= DateTime.Now)
            {

                if(userExists != null)
                {
                    //revogar pois pode ser um ataque
                    userExists.RefreshToken = null;
                    userExists.RefreshTokenExpiryTime = null;

                    await userManager.UpdateAsync(userExists);
                }

                return Results.BadRequest(new AuthenticationResponseDTO()
                {
                    Result = false,
                    Errors = new List<object>() { "Requisição inválida." }
                });

            }

            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, userExists.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            if (userExists.UserName == "ADM")
            {
                authClaims.Add(new Claim(ClaimTypes.Role, "EMPRESAS:CONSULTAR"));
                authClaims.Add(new Claim(ClaimTypes.Role, "EMPRESAS:INCLUIR"));
                authClaims.Add(new Claim(ClaimTypes.Role, "EMPRESAS:ALTERAR"));
                authClaims.Add(new Claim(ClaimTypes.Role, "EMPRESAS:EXCLUIR"));
            }

            var token = new JwtSecurityTokenHandler().WriteToken(GenerateToken(authClaims, builder.Configuration));
            var refreshToken = GenerateRefreshToken();

            userExists.RefreshToken = refreshToken;
            await userManager.UpdateAsync(userExists);

            return Results.Ok(new AuthenticationResponseDTO()
            {
                Result = true,
                Token = token,
                RefreshToken = refreshToken
            });
        });
        #endregion

        #region Logout
        app.MapPost("auth/logout", [Authorize] async ([FromServices] UserManager<WebApplication1UserEntity> userManager,
                                                    ClaimsPrincipal user,
                                                    CancellationToken cancellationToken) =>
        {

            var userExists = await userManager.FindByNameAsync(user!.Identity!.Name);
            userExists.RefreshToken = null;
            userExists.RefreshTokenExpiryTime = null;

            await userManager.UpdateAsync(userExists);

            return Results.Ok(new AuthenticationResponseDTO()
            {
                Result = true
            });

        });
        #endregion

        #region Empresas
        app.MapPost("empresas/insert", [Authorize(Roles = "EMPRESAS:INCLUIR")] async ([FromServices] WebApplication1DbContext dbContext,
                                                                                      [FromBody] EmpresasTableDTO empresasTableDTO,
                                                                                      CancellationToken cancellationToken) =>
        {
            var query = await dbContext.EmpresasTable.AddAsync(new()
            {
                CodigoEmpresa = empresasTableDTO.CodigoEmpresa,
                NomeEmpresa = empresasTableDTO.NomeEmpresa,
                Ativo = empresasTableDTO.Ativo
            },cancellationToken);

            await dbContext.SaveChangesAsync(cancellationToken);

            return Results.Ok();

        });

        app.MapGet("empresas/select", [Authorize(Roles = "EMPRESAS:CONSULTAR")] async ([FromServices] WebApplication1DbContext dbContext,
                                                                                      CancellationToken cancellationToken) =>
        {
            var query = await dbContext.EmpresasTable.Select(e => new EmpresasTableDTO
            {
                CodigoEmpresa = e.CodigoEmpresa!.Value,
                NomeEmpresa = e.NomeEmpresa,
                Ativo = e.Ativo

            }).ToListAsync(cancellationToken);

            return Results.Ok(query);

        });

        #endregion

        #region Hubs
        app.MapHub<SyncHub>("/hubs/sync");
        #endregion

        await app.RunAsync();
    }

    #region DTOs
    public class RegisterDTO
    {
        [Required(ErrorMessage = "Usuário é requerido.")]
        public string Usuario { get; set; } = null!;
        [EmailAddress]
        [Required(ErrorMessage = "E-mail é requerido.")]
        public string Email { get; set; } = null!;
        [Required(ErrorMessage = "Senha é requerido.")]
        public string Senha { get; set; } = null!;
    }

    public class LoginDTO
    {
        [Required(ErrorMessage = "Usuário é requerido.")]
        public string Usuario { get; set; } = null!;
        [Required(ErrorMessage = "Senha é requerido.")]
        public string Senha { get; set; } = null!;
    }

    public class RefreshDTO
    {
        [Required(ErrorMessage = "Token é requerido.")]
        public string Token { get; set; } = null!;
        [Required(ErrorMessage = "RefreshToken é requerido.")]
        public string RefreshToken { get; set; } = null!;
    }


    public class AuthenticationResponseDTO
    {
        public List<object>? Errors { get; set; }
        public bool Result { get; set; }
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }


    }


    public class EmpresasTableDTO
    {
        [Required(ErrorMessage = "Código Empresa é requerido.")]
        public int CodigoEmpresa { get; set; }
        [Required(ErrorMessage = "Nome Empresa é requerido.")]
        public string NomeEmpresa { get; set; } = null!;
        [Required(ErrorMessage = "Ativo é requerido.")]
        public bool Ativo { get; set; }
    }

    #endregion

    #region Hubs
    public interface ISyncHub
    {
        Task ResponseEmpresasSelect(List<EmpresasTableDTO> empresasTableDTOs);
        Task ResponseEmpresasInsert(bool inserted);
        //Task<List<EmpresasTableDTO>> RequestEmpresasSelect1();
    }
    public class SyncHub : Hub<ISyncHub>
    {
        private WebApplication1DbContext _dbContext { get; init; }

        public SyncHub(WebApplication1DbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task RequestEmpresasSelect()
        {
            var query = await _dbContext.EmpresasTable.Select(e=> new EmpresasTableDTO()
            {
                CodigoEmpresa = e.CodigoEmpresa!.Value,
                NomeEmpresa = e.NomeEmpresa,
                Ativo = e.Ativo
            }).ToListAsync();
            await Clients.Caller.ResponseEmpresasSelect(query);
        }

        public async Task<List<EmpresasTableDTO>> RequestEmpresasSelect1()
        {
            var query = await _dbContext.EmpresasTable.Select(e => new EmpresasTableDTO()
            {
                CodigoEmpresa = e.CodigoEmpresa!.Value,
                NomeEmpresa = e.NomeEmpresa,
                Ativo = e.Ativo
            }).ToListAsync();
            return query;
        }

        public async Task RequestEmpresasInsert(EmpresasTableDTO empresasTableDTO)
        {
            var query = await _dbContext.EmpresasTable.AddAsync(new()
            {
                CodigoEmpresa = empresasTableDTO.CodigoEmpresa,
                NomeEmpresa = empresasTableDTO.NomeEmpresa,
                Ativo = empresasTableDTO.Ativo
            });

            await _dbContext.SaveChangesAsync();
            await Clients.Caller.ResponseEmpresasInsert(true);
        }
    }
    #endregion

    #region Token Handlers

    private static JwtSecurityToken GenerateToken(List<Claim> authClaims,IConfiguration configuration)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
        var parsed = int.TryParse(configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

        var token = new JwtSecurityToken(issuer: configuration["JWT:ValidAudience"],
                                         audience: configuration["JWT:ValidIssuer"],
                                         //expires: DateTime.Now.AddMinutes(parsed ? tokenValidityInMinutes : 1),
                                         expires: DateTime.Now.AddMinutes(1),
                                         claims: authClaims,
                                         signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

        return token;
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
    private static ClaimsPrincipal GetPrincipalFromExpiredToken(string token,IConfiguration configuration)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"])),
            ValidateLifetime = false,
            ValidIssuer = configuration["JWT:ValidIssuer"],
            ValidAudience = configuration["JWT:ValidAudience"],
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
        var jwtSecurityToken = securityToken as JwtSecurityToken;
        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }

    #endregion
}


