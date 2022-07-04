using System;

namespace MauiApp1.Entities.Empresas
{
    public class EmpresasEntity
    {
        public virtual Guid? Id { get; set; }
        public virtual int? CodigoEmpresa { get; set; }
        public virtual string NomeEmpresa { get; set; } = null!;
        public virtual bool Ativo { get; set; }
    }
}
