using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using WebApplication1.Entities.Empresas;
using WebApplication1.Entities.WebApplication1Role;
using WebApplication1.Entities.WebApplication1RoleClaim;
using WebApplication1.Entities.WebApplication1User;
using WebApplication1.Entities.WebApplication1UserClaim;
using WebApplication1.Entities.WebApplication1UserLogin;
using WebApplication1.Entities.WebApplication1UserRole;
using WebApplication1.Entities.WebApplication1UserToken;

namespace WebApplication1.Entities
{
    public class WebApplication1DbContext : IdentityDbContext<WebApplication1UserEntity,
                                                              WebApplication1RoleEntity,
                                                              Guid,
                                                              WebApplication1UserClaimEntity,
                                                              WebApplication1UserRoleEntity,
                                                              WebApplication1UserLoginEntity,
                                                              WebApplication1RoleClaimEntity,
                                                              WebApplication1UserTokenEntity>
    {

        public WebApplication1DbContext()
        {

        }

        public WebApplication1DbContext(DbContextOptions options) : base(options)
        {
        }

        public virtual DbSet<EmpresasEntity> EmpresasTable { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<EmpresasEntity>().ToTable("empresas", "dbo");
            modelBuilder.Entity<EmpresasEntity>().HasKey(e => e.Id).HasName("PK_empresas_id");
            modelBuilder.Entity<EmpresasEntity>().HasIndex(e => e.CodigoEmpresa).IsUnique(true).HasDatabaseName("UK_empresas_codigo_empresa");
            modelBuilder.Entity<EmpresasEntity>().Property(e=> e.Id).HasColumnName("id").HasColumnType("UNIQUEIDENTIFIER").IsRequired(true).HasDefaultValueSql("NEWSEQUENTIALID()");
            modelBuilder.Entity<EmpresasEntity>().Property(e => e.CodigoEmpresa).HasColumnName("codigo_empresa").HasColumnType("INT").IsRequired(true);
            modelBuilder.Entity<EmpresasEntity>().Property(e => e.NomeEmpresa).HasColumnName("nome_empresa").HasColumnType("NVARCHAR(100)").IsRequired(true);
            modelBuilder.Entity<EmpresasEntity>().Property(e => e.Ativo).HasColumnName("ativo").HasColumnType("BIT").IsRequired(true);

            modelBuilder.Entity<WebApplication1UserEntity>().Property(e => e.RefreshToken).HasColumnName("refreshtoken").HasColumnType("NVARCHAR(MAX)").IsRequired(false);
            //ele não reconhece o tipo DATETIMEOFFSET(7)
            modelBuilder.Entity<WebApplication1UserEntity>().Property(e => e.RefreshTokenExpiryTime).HasColumnName("refreshtoken_expirytime").IsRequired(false);
        }
    }
}
