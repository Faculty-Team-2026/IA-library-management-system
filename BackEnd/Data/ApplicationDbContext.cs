using BackEnd.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace BackEnd.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Book> Books { get; set; }
        public DbSet<Location> Locations { get; set; }
        public DbSet<BorrowRequest> BorrowRequests { get; set; }
        public DbSet<BorrowRecord> BorrowRecords { get; set; }
        public DbSet<LibrarianRequest> LibrarianRequests { get; set; }
        public DbSet<Membership> Memberships { get; set; }
        public DbSet<UserMembership> UserMemberships { get; set; }
        public DbSet<ChatMessage> ChatMessages { get; set; }
        public DbSet<SystemLog> SystemLogs { get; set; }


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure User
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Username)
                .IsUnique();

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            modelBuilder.Entity<User>()
                .HasIndex(u => u.SSN)
                .IsUnique();

            // Configure Book
            modelBuilder.Entity<Book>()
                .HasIndex(b => b.ISBN)
                .IsUnique();

            // Configure BorrowRequest
            modelBuilder.Entity<BorrowRequest>()
                .HasOne(br => br.User)
                .WithMany(u => u.BorrowRequests)
                .HasForeignKey(br => br.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<BorrowRequest>()
                .HasOne(br => br.Book)
                .WithMany(b => b.BorrowRequests)
                .HasForeignKey(br => br.BookId)
                .OnDelete(DeleteBehavior.Cascade);

            // Configure BorrowRecord
            modelBuilder.Entity<BorrowRecord>()
                .HasOne(br => br.User)
                .WithMany(u => u.BorrowRecords)
                .HasForeignKey(br => br.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<BorrowRecord>()
                .HasOne(br => br.Book)
                .WithMany(b => b.BorrowRecords)
                .HasForeignKey(br => br.BookId)
                .IsRequired(false)
                .OnDelete(DeleteBehavior.SetNull);

            // Configure UserMembership - UPDATED SECTION
            modelBuilder.Entity<UserMembership>()
                .HasOne(um => um.User)
                .WithMany(u => u.UserMemberships)
                .HasForeignKey(um => um.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<UserMembership>()
                .HasOne(um => um.Membership)
                .WithMany(m => m.UserMemberships)
                .HasForeignKey(um => um.MembershipId)
                .OnDelete(DeleteBehavior.Cascade);

            //modelBuilder.Entity<UserMembership>()
            //    .HasOne(um => um.ParentUser)
            //    .WithMany(u => u.FamilyMembers)
            //    .HasForeignKey(um => um.ParentUserId)
            //    .OnDelete(DeleteBehavior.NoAction);

            // Configure LibrarianRequest
            modelBuilder.Entity<LibrarianRequest>()
                .HasOne(lr => lr.User)
                .WithMany(u => u.LibrarianRequests)
                .HasForeignKey(lr => lr.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Configure ChatMessage
            modelBuilder.Entity<ChatMessage>()
                .HasOne(cm => cm.User)
                .WithMany()
                .HasForeignKey(cm => cm.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Location>()
                .Property(l => l.Name)
                .IsRequired();

            modelBuilder.Entity<Location>()
                .Property(l => l.Latitude)
                .IsRequired();

            modelBuilder.Entity<Location>()
                .Property(l => l.Longitude)
                .IsRequired();

            SeedData(modelBuilder);
        }

        private void SeedData(ModelBuilder modelBuilder)
        {
            // Seed Books
            modelBuilder.Entity<Book>().HasData(
                new Book
                {
                    Id = 1,
                    Title = "The Great Gatsby",
                    Author = "F. Scott Fitzgerald",
                    ISBN = "978-3-16-148410-0",
                    PublishedDate = new DateTime(1925, 4, 10),
                    Available = true,
                    Quantity = 5,
                    Description = "A novel of lyrical beauty and uncompromising vision, The Great Gatsby is the story of the fabulously wealthy Jay Gatsby and his love for the beautiful Daisy Buchanan. Set in the Jazz Age on Long Island, the novel depicts the excesses of the American Dream through the eyes of Nick Carraway."
                },
                new Book
                {
                    Id = 2,
                    Title = "To Kill a Mockingbird",
                    Author = "Harper Lee",
                    ISBN = "978-1-23-456789-0",
                    PublishedDate = new DateTime(1960, 7, 11),
                    Available = true,
                    Quantity = 3,
                    Description = "The unforgettable novel of a childhood in a sleepy Southern town and the crisis of conscience that rocked it. To Kill a Mockingbird became both an instant bestseller and a critical success when it was first published in 1960. It went on to win the Pulitzer Prize in 1961 and was later made into an Academy Award-winning film."
                },
                new Book
                {
                    Id = 3,
                    Title = "1984",
                    Author = "George Orwell",
                    ISBN = "978-0-45-152493-5",
                    PublishedDate = new DateTime(1949, 6, 8),
                    Available = true,
                    Quantity = 4,
                    Description = "A dystopian social science fiction novel and cautionary tale. The novel is set in a totalitarian society where critical thought is suppressed. The novel follows the life of Winston Smith, a low-ranking member of 'the Party', who is frustrated by the omnipresent eyes of the party, and its ominous ruler Big Brother."
                },
                new Book
                {
                    Id = 4,
                    Title = "Pride and Prejudice",
                    Author = "Jane Austen",
                    ISBN = "978-0-14-143951-8",
                    PublishedDate = new DateTime(1813, 1, 28),
                    Available = true,
                    Quantity = 6,
                    Description = "A romantic novel of manners that follows the character development of Elizabeth Bennet, the dynamic protagonist of the book who learns about the repercussions of hasty judgments and comes to appreciate the difference between superficial goodness and actual goodness."
                },
                new Book
                {
                    Id = 5,
                    Title = "The Catcher in the Rye",
                    Author = "J.D. Salinger",
                    ISBN = "978-0-31-676948-8",
                    PublishedDate = new DateTime(1951, 7, 16),
                    Available = true,
                    Quantity = 3,
                    Description = "The story of Holden Caulfield, a teenager who has been expelled from his prep school. The novel follows Holden's experiences in New York City in the days following his expulsion, as he struggles with alienation, loss of innocence, and the phoniness of the adult world."
                },
                new Book
                {
                    Id = 6,
                    Title = "The Hobbit",
                    Author = "J.R.R. Tolkien",
                    ISBN = "978-0-54-792822-7",
                    PublishedDate = new DateTime(1937, 9, 21),
                    Available = true,
                    Quantity = 4,
                    Description = "A fantasy novel and children's book by English author J. R. R. Tolkien. It follows the quest of home-loving hobbit Bilbo Baggins to win a share of the treasure guarded by Smaug the dragon. Bilbo's journey takes him from his peaceful rural surroundings into more sinister territory."
                },
                new Book
                {
                    Id = 7,
                    Title = "The Alchemist",
                    Author = "Paulo Coelho",
                    ISBN = "978-0-06-231500-7",
                    PublishedDate = new DateTime(1988, 1, 1),
                    Available = true,
                    Quantity = 5,
                    Description = "A philosophical novel that follows the journey of an Andalusian shepherd boy named Santiago. Believing a recurring dream to be prophetic, he decides to travel to a Romani fortune-teller in a nearby town to discover its meaning. The book's main theme is about finding one's destiny."
                },
                new Book
                {
                    Id = 8,
                    Title = "The Little Prince",
                    Author = "Antoine de Saint-Exupéry",
                    ISBN = "978-0-15-601398-7",
                    PublishedDate = new DateTime(1943, 4, 6),
                    Available = true,
                    Quantity = 3,
                    Description = "A poetic tale, with watercolor illustrations by the author, in which a pilot stranded in the desert meets a young prince fallen to Earth from a tiny asteroid. The story is philosophical and includes social criticism, remarking on the strangeness of the adult world."
                },
                new Book
                {
                    Id = 9,
                    Title = "The Da Vinci Code",
                    Author = "Dan Brown",
                    ISBN = "978-0-30-747427-8",
                    PublishedDate = new DateTime(2003, 3, 18),
                    Available = true,
                    Quantity = 4,
                    Description = "A mystery thriller novel that follows symbologist Robert Langdon and cryptologist Sophie Neveu after a murder in the Louvre Museum in Paris causes them to become involved in a battle between the Priory of Sion and Opus Dei over the possibility of Jesus having been married to Mary Magdalene."
                },
                new Book
                {
                    Id = 10,
                    Title = "The Kite Runner",
                    Author = "Khaled Hosseini",
                    ISBN = "978-1-59-463193-1",
                    PublishedDate = new DateTime(2003, 5, 29),
                    Available = true,
                    Quantity = 3,
                    Description = "A story of friendship, betrayal, and the price of loyalty. It tells the story of Amir, a young boy from Kabul, and his friend Hassan, the son of his father's servant. The story is set against a backdrop of tumultuous events, from the fall of Afghanistan's monarchy through the Soviet military intervention, the exodus of refugees to Pakistan and the United States, and the rise of the Taliban regime."
                }
            );

            // Seed Memberships
            modelBuilder.Entity<Membership>().HasData(
                new Membership
                {
                    MembershipId = 1,
                    MembershipType = "Standard",
                    BorrowLimit = 5,
                    DurationInDays = 30,
                    Price = 9.99m,
                    Description = "Standard membership with a borrow limit of 5 books.",
                    IsFamilyPlan = false,
                    MaxFamilyMembers = null,
                    RequiresApproval = true,
                    CreatedAt = new DateTime(2025, 4, 1)
                },
                new Membership
                {
                    MembershipId = 2,
                    MembershipType = "Premium",
                    BorrowLimit = 15,
                    DurationInDays = 60,
                    Price = 24.99m,
                    Description = "Premium membership with extended duration and higher borrow limit.",
                    IsFamilyPlan = false,
                    MaxFamilyMembers = null,
                    RequiresApproval = false,
                    CreatedAt = new DateTime(2025, 4, 1)
                }
            );
        }

    }
}