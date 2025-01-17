﻿using BaseCode.Data.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace BaseCode.Data
{
    public partial class BaseCodeEntities : IdentityDbContext<IdentityUser>
    {
        public BaseCodeEntities(DbContextOptions<BaseCodeEntities> options) 
            : base(options)
        { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Disables cascade delete for tables with foreign key relationships
            var cascadeTables = modelBuilder.Model.GetEntityTypes()
                .SelectMany(foreignKeysTables => foreignKeysTables.GetForeignKeys())
                .Where(foreignKeysTables => !foreignKeysTables.IsOwnership && 
                       foreignKeysTables.DeleteBehavior == DeleteBehavior.Cascade);


            foreach (var table in cascadeTables)
            {
                table.DeleteBehavior = DeleteBehavior.Restrict;
            }
            
            base.OnModelCreating(modelBuilder);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            optionsBuilder.EnableSensitiveDataLogging();
        }

        public virtual DbSet<PersonalInformation> PersonalInformation { get; set; }
        public virtual DbSet<JobRequirement> JobRequirement { get; set; }
        public virtual DbSet<JobDescription> JobDescription { get; set; }
        public virtual DbSet<Attachment> Attachment { get; set; }
        public virtual DbSet<Job> Jobs { get; set; }
        public virtual DbSet<Application> Applications { get; set; }
        public virtual DbSet<User> User { get; set; }
        public virtual DbSet<RefreshToken> RefreshToken { get; set; }
    }
}
