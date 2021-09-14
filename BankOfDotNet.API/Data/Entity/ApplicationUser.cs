using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace BankOfDotNet.Data.Entity
{
    public class ApplicationUser : IdentityUser
    {

        [Required]
        [MaxLength(12)]
        public string FullName { get; set; }
        [Required]
        public string ImgUrl { get; set; }
        public string EmployeeCode { get; set; }
        public int? CompanyId { get; set; }
        //public Company Company { get; set; }

        public bool IsVerified { get; set; }
        public bool IsActive { get; set; }
        public bool IsDeleted { get; set; }

        [MaxLength(120)]
        public string CreatedBy { get; set; }
        public DateTime? CreatedAt { get; set; }
        [MaxLength(120)]
        public string UpdatedBy { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public int? UpdateCount { get; set; }


    }
}
