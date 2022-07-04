using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MauiApp1.Authentication
{
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


}
