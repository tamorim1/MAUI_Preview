// See https://aka.ms/new-console-template for more information
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

using var context = new MyDbContext();

context.EmpresasTable.Add(new Empresas()
{
    Codigo = 1,
    Nome = "teste"
});

context.SaveChanges();

var empresas = context.EmpresasTable.First();

Console.WriteLine(empresas.Codigo);
Console.WriteLine(empresas.Nome);





public class Empresas
{
    public virtual int Codigo { get; set; }
    public virtual string Nome { get; set; } = null!;
}

public class MyDbContext : DbContext
{

    public virtual DbSet<Empresas> EmpresasTable { get; set; }

    public MyDbContext()
    {
        //verificar o linker
        SQLitePCL.Batteries_V2.Init();
        Database.EnsureDeleted();
        Database.EnsureCreated();
    }

    public MyDbContext(DbContextOptions dbContextOptions)
    {

    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        var connectionString = new SqliteConnectionStringBuilder()
        {
            DataSource = "meubanco.db",
            Password = "123456789",
            Mode = SqliteOpenMode.ReadWriteCreate
        };

        optionsBuilder.UseSqlite(new SqliteConnection(connectionString.ToString()));
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Empresas>().ToTable("empresas");
        modelBuilder.Entity<Empresas>().HasKey(e => e.Codigo).HasName("PK_empresas_codigo");
        modelBuilder.Entity<Empresas>().Property(e => e.Codigo).HasColumnName("codigo").HasColumnType("INTEGER").IsRequired(true);
        modelBuilder.Entity<Empresas>().Property(e => e.Nome).HasColumnName("nome").HasColumnType("TEXT").IsRequired(true);
        
    }
}