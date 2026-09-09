using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration; 

namespace For_Testing_Only_Capstone.Models;

public abstract partial class RegistrarDbContext : DbContext
{
    protected readonly IConfiguration? _configuration;

    protected RegistrarDbContext()
    {
    }

    protected RegistrarDbContext(DbContextOptions options, IConfiguration configuration)
        : base(options)
    {
        _configuration = configuration;
    }

    public virtual DbSet<Gradecorrectionlog> Gradecorrectionlogs { get; set; }

    public virtual DbSet<Userrequest> Userrequests { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            string? connectionString = _configuration?.GetConnectionString("PostgresConnection");
            
            if (string.IsNullOrEmpty(connectionString))
            {
                throw new InvalidOperationException("The connection string 'PostgresConnection' is missing from configuration.");
            }

            optionsBuilder.UseNpgsql(connectionString);
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Gradecorrectionlog>(entity =>
        {
            entity.HasKey(e => e.Logid).HasName("gradecorrectionlogs_pkey");

            entity.ToTable("gradecorrectionlogs");

            entity.Property(e => e.Logid).HasColumnName("logid");
            entity.Property(e => e.Approvedby)
                .HasMaxLength(100)
                .HasColumnName("approvedby");
            entity.Property(e => e.Newgrade)
                .HasMaxLength(10)
                .HasColumnName("newgrade");
            entity.Property(e => e.Oldgrade)
                .HasMaxLength(10)
                .HasColumnName("oldgrade");
            entity.Property(e => e.Reasontext).HasColumnName("reasontext");
            entity.Property(e => e.Recordid)
                .HasMaxLength(100)
                .HasColumnName("recordid");
            entity.Property(e => e.Timestamp)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("timestamp");
        });

        modelBuilder.Entity<Userrequest>(entity =>
        {
            entity.HasKey(e => e.Requestid).HasName("userrequests_pkey");

            entity.ToTable("userrequests");

            entity.HasIndex(e => e.Email, "userrequests_email_key").IsUnique();

            entity.Property(e => e.Requestid).HasColumnName("requestid");
            
            entity.Property(e => e.Department)
                .HasMaxLength(50)
                .HasColumnName("department");

            entity.Property(e => e.Createdat)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("timestamp without time zone")
                .HasColumnName("createdat");
            entity.Property(e => e.Email)
                .HasMaxLength(100)
                .HasColumnName("email");
            entity.Property(e => e.Fullname)
                .HasMaxLength(100)
                .HasColumnName("fullname");
            entity.Property(e => e.Requeststatus)
                .HasMaxLength(20)
                .HasDefaultValueSql("'PENDING'::character varying")
                .HasColumnName("requeststatus");
            entity.Property(e => e.Role)
                .HasMaxLength(20)
                .HasColumnName("role");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}

public class RegistrarWriteDbContext : RegistrarDbContext
{
    public RegistrarWriteDbContext(DbContextOptions<RegistrarWriteDbContext> options, IConfiguration configuration) 
        : base(options, configuration)
    {
    }
}

public class RegistrarReadDbContext : RegistrarDbContext
{
    public RegistrarReadDbContext(DbContextOptions<RegistrarReadDbContext> options, IConfiguration configuration) 
        : base(options, configuration)
    {
        ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
    }
}