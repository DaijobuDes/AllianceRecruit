﻿// <auto-generated />
using System;
using BaseCode.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace BaseCode.Data.Migrations
{
    [DbContext(typeof(BaseCodeEntities))]
    partial class BaseCodeEntitiesModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "2.2.6-servicing-10079")
                .HasAnnotation("Relational:MaxIdentifierLength", 128)
                .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

            modelBuilder.Entity("BaseCode.Data.Models.Application", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnName("ApplicationId")
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("AttachmentId")
                        .HasColumnName("AttachmentId");

                    b.Property<DateTime>("DateTimeApplied")
                        .HasColumnName("DateTimeApplied");

                    b.Property<int>("JobId")
                        .HasColumnName("JobId");

                    b.Property<int>("PersonalInformationId")
                        .HasColumnName("PersonalInformationId");

                    b.Property<string>("Status")
                        .HasColumnName("Status");

                    b.HasKey("Id");

                    b.HasIndex("AttachmentId");

                    b.HasIndex("JobId");

                    b.HasIndex("PersonalInformationId");

                    b.ToTable("Applications");
                });

            modelBuilder.Entity("BaseCode.Data.Models.Attachment", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnName("AttachmentId")
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("FormalPhoto")
                        .HasColumnName("FormalPhoto");

                    b.Property<string>("LinkedInProfile")
                        .HasColumnName("LinkedInProfile");

                    b.Property<string>("PortfolioUrl")
                        .HasColumnName("PortfolioUrl");

                    b.Property<string>("Resume")
                        .HasColumnName("Resume");

                    b.HasKey("Id");

                    b.ToTable("Attachment");
                });

            modelBuilder.Entity("BaseCode.Data.Models.Job", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnName("JobId")
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("JobTitle")
                        .HasColumnName("JobTitle");

                    b.Property<string>("Location")
                        .HasColumnName("Location");

                    b.HasKey("Id");

                    b.ToTable("Jobs");
                });

            modelBuilder.Entity("BaseCode.Data.Models.JobDescription", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnName("JobDescriptionId")
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("Description")
                        .HasColumnName("Description");

                    b.Property<int?>("JobDescriptionId")
                        .HasColumnName("JobDescriptionId1");

                    b.Property<int>("JobId");

                    b.HasKey("Id");

                    b.HasIndex("JobDescriptionId");

                    b.HasIndex("JobId");

                    b.ToTable("JobDescription");
                });

            modelBuilder.Entity("BaseCode.Data.Models.JobRequirement", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnName("JobRequirementId")
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("JobId");

                    b.Property<int?>("JobRequirementId")
                        .HasColumnName("JobRequirementId1");

                    b.Property<string>("Requirement")
                        .HasColumnName("Requirement");

                    b.HasKey("Id");

                    b.HasIndex("JobId");

                    b.HasIndex("JobRequirementId");

                    b.ToTable("JobRequirement");
                });

            modelBuilder.Entity("BaseCode.Data.Models.PersonalInformation", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnName("PersonalInformationId")
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("AddressLine1")
                        .HasColumnName("AddressLine1");

                    b.Property<string>("AddressLine2")
                        .HasColumnName("AddressLine2");

                    b.Property<string>("Country")
                        .HasColumnName("Country");

                    b.Property<DateTime>("DateOfBirth")
                        .HasColumnName("DateOfBirth");

                    b.Property<string>("EmailAddress")
                        .HasColumnName("EmailAddress");

                    b.Property<string>("FirstName")
                        .HasColumnName("FirstName")
                        .HasColumnType("varchar(250)");

                    b.Property<string>("LastName")
                        .HasColumnName("LastName")
                        .HasColumnType("varchar(250)");

                    b.Property<string>("MiddleName")
                        .HasColumnName("MiddleName")
                        .HasColumnType("varchar(250)");

                    b.Property<string>("PhoneNumber")
                        .HasColumnName("PhoneNumber");

                    b.Property<string>("Province")
                        .HasColumnName("Province");

                    b.Property<string>("Sex")
                        .HasColumnName("Sex");

                    b.Property<string>("ZipCode")
                        .HasColumnName("ZipCode");

                    b.HasKey("Id");

                    b.ToTable("PersonalInformation");
                });

            modelBuilder.Entity("BaseCode.Data.Models.RefreshToken", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime>("ExpiresUtc");

                    b.Property<DateTime>("IssuedUtc");

                    b.Property<string>("Token");

                    b.Property<string>("Username");

                    b.HasKey("Id");

                    b.ToTable("RefreshToken");
                });

            modelBuilder.Entity("BaseCode.Data.Models.User", b =>
                {
                    b.Property<string>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("Address");

                    b.Property<string>("CreatedBy");

                    b.Property<DateTime?>("CreatedDate");

                    b.Property<string>("FirstName");

                    b.Property<string>("LastName");

                    b.Property<string>("ModifiedBy");

                    b.Property<DateTime?>("ModifiedDate");

                    b.Property<string>("UserID");

                    b.Property<string>("Username");

                    b.HasKey("Id");

                    b.ToTable("User");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityRole", b =>
                {
                    b.Property<string>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("ConcurrencyStamp")
                        .IsConcurrencyToken();

                    b.Property<string>("Name")
                        .HasMaxLength(256);

                    b.Property<string>("NormalizedName")
                        .HasMaxLength(256);

                    b.HasKey("Id");

                    b.HasIndex("NormalizedName")
                        .IsUnique()
                        .HasName("RoleNameIndex")
                        .HasFilter("[NormalizedName] IS NOT NULL");

                    b.ToTable("AspNetRoles");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityRoleClaim<string>", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("ClaimType");

                    b.Property<string>("ClaimValue");

                    b.Property<string>("RoleId")
                        .IsRequired();

                    b.HasKey("Id");

                    b.HasIndex("RoleId");

                    b.ToTable("AspNetRoleClaims");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUser", b =>
                {
                    b.Property<string>("Id")
                        .ValueGeneratedOnAdd();

                    b.Property<int>("AccessFailedCount");

                    b.Property<string>("ConcurrencyStamp")
                        .IsConcurrencyToken();

                    b.Property<string>("Email")
                        .HasMaxLength(256);

                    b.Property<bool>("EmailConfirmed");

                    b.Property<bool>("LockoutEnabled");

                    b.Property<DateTimeOffset?>("LockoutEnd");

                    b.Property<string>("NormalizedEmail")
                        .HasMaxLength(256);

                    b.Property<string>("NormalizedUserName")
                        .HasMaxLength(256);

                    b.Property<string>("PasswordHash");

                    b.Property<string>("PhoneNumber");

                    b.Property<bool>("PhoneNumberConfirmed");

                    b.Property<string>("SecurityStamp");

                    b.Property<bool>("TwoFactorEnabled");

                    b.Property<string>("UserName")
                        .HasMaxLength(256);

                    b.HasKey("Id");

                    b.HasIndex("NormalizedEmail")
                        .HasName("EmailIndex");

                    b.HasIndex("NormalizedUserName")
                        .IsUnique()
                        .HasName("UserNameIndex")
                        .HasFilter("[NormalizedUserName] IS NOT NULL");

                    b.ToTable("AspNetUsers");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserClaim<string>", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("ClaimType");

                    b.Property<string>("ClaimValue");

                    b.Property<string>("UserId")
                        .IsRequired();

                    b.HasKey("Id");

                    b.HasIndex("UserId");

                    b.ToTable("AspNetUserClaims");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserLogin<string>", b =>
                {
                    b.Property<string>("LoginProvider");

                    b.Property<string>("ProviderKey");

                    b.Property<string>("ProviderDisplayName");

                    b.Property<string>("UserId")
                        .IsRequired();

                    b.HasKey("LoginProvider", "ProviderKey");

                    b.HasIndex("UserId");

                    b.ToTable("AspNetUserLogins");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserRole<string>", b =>
                {
                    b.Property<string>("UserId");

                    b.Property<string>("RoleId");

                    b.HasKey("UserId", "RoleId");

                    b.HasIndex("RoleId");

                    b.ToTable("AspNetUserRoles");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserToken<string>", b =>
                {
                    b.Property<string>("UserId");

                    b.Property<string>("LoginProvider");

                    b.Property<string>("Name");

                    b.Property<string>("Value");

                    b.HasKey("UserId", "LoginProvider", "Name");

                    b.ToTable("AspNetUserTokens");
                });

            modelBuilder.Entity("BaseCode.Data.Models.Application", b =>
                {
                    b.HasOne("BaseCode.Data.Models.Attachment", "Attachment")
                        .WithMany()
                        .HasForeignKey("AttachmentId")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.HasOne("BaseCode.Data.Models.Job", "Job")
                        .WithMany()
                        .HasForeignKey("JobId")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.HasOne("BaseCode.Data.Models.PersonalInformation", "PersonalInformation")
                        .WithMany()
                        .HasForeignKey("PersonalInformationId")
                        .OnDelete(DeleteBehavior.Restrict);
                });

            modelBuilder.Entity("BaseCode.Data.Models.JobDescription", b =>
                {
                    b.HasOne("BaseCode.Data.Models.JobDescription")
                        .WithMany("JobDescriptions")
                        .HasForeignKey("JobDescriptionId");

                    b.HasOne("BaseCode.Data.Models.Job", "Job")
                        .WithMany("JobDescriptions")
                        .HasForeignKey("JobId")
                        .OnDelete(DeleteBehavior.Restrict);
                });

            modelBuilder.Entity("BaseCode.Data.Models.JobRequirement", b =>
                {
                    b.HasOne("BaseCode.Data.Models.Job", "Job")
                        .WithMany("JobRequirements")
                        .HasForeignKey("JobId")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.HasOne("BaseCode.Data.Models.JobRequirement")
                        .WithMany("JobRequirements")
                        .HasForeignKey("JobRequirementId");
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityRoleClaim<string>", b =>
                {
                    b.HasOne("Microsoft.AspNetCore.Identity.IdentityRole")
                        .WithMany()
                        .HasForeignKey("RoleId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserClaim<string>", b =>
                {
                    b.HasOne("Microsoft.AspNetCore.Identity.IdentityUser")
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserLogin<string>", b =>
                {
                    b.HasOne("Microsoft.AspNetCore.Identity.IdentityUser")
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserRole<string>", b =>
                {
                    b.HasOne("Microsoft.AspNetCore.Identity.IdentityRole")
                        .WithMany()
                        .HasForeignKey("RoleId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("Microsoft.AspNetCore.Identity.IdentityUser")
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Microsoft.AspNetCore.Identity.IdentityUserToken<string>", b =>
                {
                    b.HasOne("Microsoft.AspNetCore.Identity.IdentityUser")
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade);
                });
#pragma warning restore 612, 618
        }
    }
}
