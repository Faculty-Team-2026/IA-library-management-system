﻿// <auto-generated />
using System;
using BackEnd.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace BackEnd.Migrations
{
    [DbContext(typeof(ApplicationDbContext))]
    [Migration("20250424044825_seedingSomeDataAndFixngChatsv2")]
    partial class seedingSomeDataAndFixngChatsv2
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "9.0.4")
                .HasAnnotation("Relational:MaxIdentifierLength", 128);

            SqlServerModelBuilderExtensions.UseIdentityColumns(modelBuilder);

            modelBuilder.Entity("BackEnd.Models.Book", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<long>("Id"));

                    b.Property<string>("Author")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<bool>("Available")
                        .HasColumnType("bit");

                    b.Property<string>("ISBN")
                        .HasColumnType("nvarchar(450)");

                    b.Property<DateTime?>("PublishedDate")
                        .HasColumnType("datetime2");

                    b.Property<int>("Quantity")
                        .HasColumnType("int");

                    b.Property<string>("Title")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.HasIndex("ISBN")
                        .IsUnique()
                        .HasFilter("[ISBN] IS NOT NULL");

                    b.ToTable("Books");

                    b.HasData(
                        new
                        {
                            Id = 1L,
                            Author = "John Doe",
                            Available = true,
                            ISBN = "978-3-16-148410-0",
                            PublishedDate = new DateTime(2020, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Quantity = 5,
                            Title = "C# Programming"
                        },
                        new
                        {
                            Id = 2L,
                            Author = "Jane Smith",
                            Available = true,
                            ISBN = "978-1-23-456789-0",
                            PublishedDate = new DateTime(2021, 5, 15, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Quantity = 3,
                            Title = "ASP.NET Core Guide"
                        });
                });

            modelBuilder.Entity("BackEnd.Models.BorrowRecord", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<long>("Id"));

                    b.Property<long>("BookId")
                        .HasColumnType("bigint");

                    b.Property<DateTime>("BorrowDate")
                        .HasColumnType("datetime2");

                    b.Property<long>("BorrowRequestId")
                        .HasColumnType("bigint");

                    b.Property<DateTime>("DueDate")
                        .HasColumnType("datetime2");

                    b.Property<DateTime?>("ReturnDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Status")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<long>("UserId")
                        .HasColumnType("bigint");

                    b.HasKey("Id");

                    b.HasIndex("BookId");

                    b.HasIndex("BorrowRequestId")
                        .IsUnique();

                    b.HasIndex("UserId");

                    b.ToTable("BorrowRecords");
                });

            modelBuilder.Entity("BackEnd.Models.BorrowRequest", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<long>("Id"));

                    b.Property<long>("BookId")
                        .HasColumnType("bigint");

                    b.Property<DateTime>("RequestDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Status")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<long>("UserId")
                        .HasColumnType("bigint");

                    b.HasKey("Id");

                    b.HasIndex("BookId")
                        .IsUnique();

                    b.HasIndex("UserId");

                    b.ToTable("BorrowRequests");
                });

            modelBuilder.Entity("BackEnd.Models.ChatMessage", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<long>("Id"));

                    b.Property<string>("GroupName")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Message")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<DateTime>("Timestamp")
                        .HasColumnType("datetime2");

                    b.Property<long>("UserId")
                        .HasColumnType("bigint");

                    b.HasKey("Id");

                    b.HasIndex("UserId");

                    b.ToTable("ChatMessages");
                });

            modelBuilder.Entity("BackEnd.Models.LibrarianRequest", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<long>("Id"));

                    b.Property<DateTime>("RequestDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Status")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<long>("UserId")
                        .HasColumnType("bigint");

                    b.HasKey("Id");

                    b.HasIndex("UserId");

                    b.ToTable("LibrarianRequests");
                });

            modelBuilder.Entity("BackEnd.Models.User", b =>
                {
                    b.Property<long>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("bigint");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<long>("Id"));

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("datetime2");

                    b.Property<string>("Email")
                        .HasMaxLength(100)
                        .HasColumnType("nvarchar(100)");

                    b.Property<string>("FirstName")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("nvarchar(50)");

                    b.Property<string>("LastName")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("nvarchar(50)");

                    b.Property<string>("Password")
                        .IsRequired()
                        .HasMaxLength(255)
                        .HasColumnType("nvarchar(255)");

                    b.Property<string>("PhoneNumber")
                        .HasMaxLength(15)
                        .HasColumnType("nvarchar(15)");

                    b.Property<string>("Role")
                        .IsRequired()
                        .HasMaxLength(20)
                        .HasColumnType("nvarchar(20)");

                    b.Property<string>("SSN")
                        .IsRequired()
                        .HasMaxLength(11)
                        .HasColumnType("nvarchar(11)");

                    b.Property<string>("Username")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("nvarchar(50)");

                    b.HasKey("Id");

                    b.HasIndex("Email")
                        .IsUnique()
                        .HasFilter("[Email] IS NOT NULL");

                    b.HasIndex("Username")
                        .IsUnique();

                    b.ToTable("Users");
                });

            modelBuilder.Entity("BackEnd.Models.UserMembership", b =>
                {
                    b.Property<int>("UserMembershipId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("UserMembershipId"));

                    b.Property<DateTime?>("EndDate")
                        .HasColumnType("datetime2");

                    b.Property<bool>("IsActive")
                        .HasColumnType("bit");

                    b.Property<bool>("IsCanceled")
                        .HasColumnType("bit");

                    b.Property<int>("MembershipId")
                        .HasColumnType("int");

                    b.Property<long?>("ParentUserId")
                        .HasColumnType("bigint");

                    b.Property<DateTime>("StartDate")
                        .HasColumnType("datetime2");

                    b.Property<string>("Status")
                        .IsRequired()
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(20)
                        .HasColumnType("nvarchar(20)")
                        .HasDefaultValue("Pending");

                    b.Property<long>("UserId")
                        .HasColumnType("bigint");

                    b.HasKey("UserMembershipId");

                    b.HasIndex("MembershipId");

                    b.HasIndex("ParentUserId");

                    b.HasIndex("UserId");

                    b.ToTable("UserMemberships");
                });

            modelBuilder.Entity("Membership", b =>
                {
                    b.Property<int>("MembershipId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("MembershipId"));

                    b.Property<int>("BorrowLimit")
                        .HasColumnType("int");

                    b.Property<DateTime>("CreatedAt")
                        .HasColumnType("datetime2");

                    b.Property<string>("Description")
                        .HasMaxLength(500)
                        .HasColumnType("nvarchar(500)");

                    b.Property<int>("DurationInDays")
                        .HasColumnType("int");

                    b.Property<bool>("IsFamilyPlan")
                        .HasColumnType("bit");

                    b.Property<int?>("MaxFamilyMembers")
                        .HasColumnType("int");

                    b.Property<string>("MembershipType")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("nvarchar(100)");

                    b.Property<decimal?>("Price")
                        .HasPrecision(18, 2)
                        .HasColumnType("decimal(18,2)");

                    b.Property<bool>("RequiresApproval")
                        .HasColumnType("bit");

                    b.HasKey("MembershipId");

                    b.ToTable("Memberships");

                    b.HasData(
                        new
                        {
                            MembershipId = 1,
                            BorrowLimit = 5,
                            CreatedAt = new DateTime(2025, 4, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Description = "Standard membership with a borrow limit of 5 books.",
                            DurationInDays = 30,
                            IsFamilyPlan = false,
                            MembershipType = "Standard",
                            Price = 9.99m,
                            RequiresApproval = false
                        },
                        new
                        {
                            MembershipId = 2,
                            BorrowLimit = 10,
                            CreatedAt = new DateTime(2025, 4, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                            Description = "Family membership with a borrow limit of 10 books.",
                            DurationInDays = 30,
                            IsFamilyPlan = true,
                            MaxFamilyMembers = 4,
                            MembershipType = "Family",
                            Price = 19.99m,
                            RequiresApproval = true
                        });
                });

            modelBuilder.Entity("BackEnd.Models.BorrowRecord", b =>
                {
                    b.HasOne("BackEnd.Models.Book", "Book")
                        .WithMany("BorrowRecords")
                        .HasForeignKey("BookId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("BackEnd.Models.BorrowRequest", "BorrowRequest")
                        .WithOne("BorrowRecord")
                        .HasForeignKey("BackEnd.Models.BorrowRecord", "BorrowRequestId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("BackEnd.Models.User", "User")
                        .WithMany("BorrowRecords")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("Book");

                    b.Navigation("BorrowRequest");

                    b.Navigation("User");
                });

            modelBuilder.Entity("BackEnd.Models.BorrowRequest", b =>
                {
                    b.HasOne("BackEnd.Models.Book", "Book")
                        .WithOne("BorrowRequest")
                        .HasForeignKey("BackEnd.Models.BorrowRequest", "BookId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("BackEnd.Models.User", "User")
                        .WithMany("BorrowRequests")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("Book");

                    b.Navigation("User");
                });

            modelBuilder.Entity("BackEnd.Models.ChatMessage", b =>
                {
                    b.HasOne("BackEnd.Models.User", "User")
                        .WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("User");
                });

            modelBuilder.Entity("BackEnd.Models.LibrarianRequest", b =>
                {
                    b.HasOne("BackEnd.Models.User", "User")
                        .WithMany("LibrarianRequests")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("User");
                });

            modelBuilder.Entity("BackEnd.Models.UserMembership", b =>
                {
                    b.HasOne("Membership", "Membership")
                        .WithMany("UserMemberships")
                        .HasForeignKey("MembershipId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.HasOne("BackEnd.Models.User", "ParentUser")
                        .WithMany("FamilyMembers")
                        .HasForeignKey("ParentUserId")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.HasOne("BackEnd.Models.User", "User")
                        .WithMany("UserMemberships")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Restrict)
                        .IsRequired();

                    b.Navigation("Membership");

                    b.Navigation("ParentUser");

                    b.Navigation("User");
                });

            modelBuilder.Entity("BackEnd.Models.Book", b =>
                {
                    b.Navigation("BorrowRecords");

                    b.Navigation("BorrowRequest")
                        .IsRequired();
                });

            modelBuilder.Entity("BackEnd.Models.BorrowRequest", b =>
                {
                    b.Navigation("BorrowRecord");
                });

            modelBuilder.Entity("BackEnd.Models.User", b =>
                {
                    b.Navigation("BorrowRecords");

                    b.Navigation("BorrowRequests");

                    b.Navigation("FamilyMembers");

                    b.Navigation("LibrarianRequests");

                    b.Navigation("UserMemberships");
                });

            modelBuilder.Entity("Membership", b =>
                {
                    b.Navigation("UserMemberships");
                });
#pragma warning restore 612, 618
        }
    }
}
