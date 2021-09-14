using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentiyServerCustom.Data.Entity
{
    public class Base
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [DefaultValue(0)]
        public int? IsDelete { get; set; }

        public DateTime? CreatedAt { get; set; }

        public DateTime? UpdatedAt { get; set; }
        [MaxLength(250)]
        public string CreatedBy { get; set; }
        [MaxLength(250)]
        public string UpdatedBy { get; set; }
    }
}
