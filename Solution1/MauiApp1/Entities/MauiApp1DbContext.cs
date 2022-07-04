using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System;
using MauiApp1.Entities.Empresas;


namespace MauiApp1.Entities
{
    public class MauiApp1DbContext : DbContext
    {

        public MauiApp1DbContext()
        {
            //testar sem o linker e sem o microsoft.data.sqlite.core
            //testar com o batteries.v2;init
            //atualizar para versão 6.0.6
            //limpar antes do build
            //usar migrations depois
            Database.EnsureDeleted();
            Database.EnsureCreated();
        }

        public MauiApp1DbContext(DbContextOptions options) : base(options)
        {

            
        }


        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            var path = Path.Combine(FileSystem.AppDataDirectory, "mauiapp1.db");

            //criptografar o arquivo com sqlcipher
            var connectionString = new SqliteConnectionStringBuilder()
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWriteCreate,
                //Password = "1234567890"
            }.ToString();
            //var connection = new SqliteConnection(connectionString);
            //optionsBuilder.UseSqlite(connection);
            optionsBuilder.UseSqlite(connectionString);
        }

        public virtual DbSet<EmpresasEntity> EmpresasTable { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<EmpresasEntity>().ToTable("empresas");
            modelBuilder.Entity<EmpresasEntity>().HasKey(e => e.Id).HasName("PK_empresas_id");
            modelBuilder.Entity<EmpresasEntity>().HasIndex(e => e.CodigoEmpresa).IsUnique(true).HasDatabaseName("UK_empresas_codigo_empresa");
            modelBuilder.Entity<EmpresasEntity>().Property(e=> e.Id).HasColumnName("id").HasColumnType("TEXT").IsRequired(true);
            modelBuilder.Entity<EmpresasEntity>().Property(e => e.CodigoEmpresa).HasColumnName("codigo_empresa").HasColumnType("INTEGER").IsRequired(true);
            modelBuilder.Entity<EmpresasEntity>().Property(e => e.NomeEmpresa).HasColumnName("nome_empresa").HasColumnType("TEXT").IsRequired(true);
            modelBuilder.Entity<EmpresasEntity>().Property(e => e.Ativo).HasColumnName("ativo").HasColumnType("INTEGER").IsRequired(true);
        }
    }
}
