using Yarp.ReverseProxy.Configuration;

namespace Client_app.Microservices;

/// <summary>
/// Defines the independently deployed ASP.NET service boundaries while keeping
/// the existing public URLs stable behind dotnet-api-gateway.
/// </summary>
public static class DotnetServiceTopology
{
    public const string Gateway = "gateway";
    public const string Auth = "auth";
    public const string Academic = "academic";
    public const string Grade = "grade";
    public const string Operations = "operations";
    public const string Realtime = "realtime";
    public const string Monolith = "monolith";

    private static readonly HashSet<string> ValidServices = new(StringComparer.OrdinalIgnoreCase)
    {
        Gateway,
        Auth,
        Academic,
        Grade,
        Operations,
        Realtime,
        Monolith
    };

    private static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> ControllerGroups =
        new Dictionary<string, IReadOnlySet<string>>(StringComparer.OrdinalIgnoreCase)
        {
            [Auth] = ControllerSet(
                "Client_app.Controllers.AuthController",
                "Client_app.Controllers.AccountManagementController",
                "Client_app.Controllers.PasswordResetRequestsController"),
            [Academic] = ControllerSet(
                "Client_app.Controllers.CurriculumsController",
                "Client_app.Controllers.GradeTemplateController",
                "Client_app.Controllers.SectioningController",
                "Client_app.Controllers.RegistrarDashboardController",
                "Client_app.Controllers.SearchController"),
            [Grade] = ControllerSet(
                "BlockGo.Controllers.GradesController",
                "BlockGo.Controllers.BulkUploadController",
                "Client_app.Controllers.StudentController"),
            [Operations] = ControllerSet(
                "Client_app.Controllers.SupportTicketsController",
                "Client_app.Controllers.SystemMonitoringController",
                "Client_app.Controllers.SystemSettingsController"),
            [Realtime] = ControllerSet()
        };

    public static string ResolveServiceName(IConfiguration configuration)
    {
        var configured = configuration["DOTNET_SERVICE_NAME"]
            ?? Environment.GetEnvironmentVariable("DOTNET_SERVICE_NAME")
            ?? Monolith;
        var normalized = configured.Trim().ToLowerInvariant().Replace('_', '-');
        normalized = normalized switch
        {
            "api-gateway" or "dotnet-api-gateway" => Gateway,
            "auth-service" or "dotnet-auth-service" => Auth,
            "academic-service" or "dotnet-academic-service" => Academic,
            "grade-service" or "dotnet-grade-service" => Grade,
            "operations-service" or "dotnet-operations-service" => Operations,
            "realtime-service" or "dotnet-realtime-service" => Realtime,
            _ => normalized
        };

        if (!ValidServices.Contains(normalized))
        {
            throw new InvalidOperationException(
                $"Unknown DOTNET_SERVICE_NAME '{configured}'. Expected one of: {string.Join(", ", ValidServices.Order())}.");
        }

        return normalized;
    }

    public static IReadOnlySet<string>? ControllersFor(string serviceName) =>
        serviceName.Equals(Monolith, StringComparison.OrdinalIgnoreCase)
            ? null
            : ControllerGroups.TryGetValue(serviceName, out var controllers)
                ? controllers
                : ControllerSet();

    public static bool HostsRealtimeHub(string serviceName) =>
        serviceName.Equals(Realtime, StringComparison.OrdinalIgnoreCase)
        || serviceName.Equals(Monolith, StringComparison.OrdinalIgnoreCase);

    public static bool RunsKeepAlive(string serviceName) =>
        serviceName.Equals(Operations, StringComparison.OrdinalIgnoreCase)
        || serviceName.Equals(Monolith, StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyDictionary<string, string> GatewayDestinations(IConfiguration configuration) =>
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [Auth] = ServiceUrl(configuration, "DOTNET_AUTH_SERVICE_URL", "dotnet-auth-service", 5101),
            [Academic] = ServiceUrl(configuration, "DOTNET_ACADEMIC_SERVICE_URL", "dotnet-academic-service", 5102),
            [Grade] = ServiceUrl(configuration, "DOTNET_GRADE_SERVICE_URL", "dotnet-grade-service", 5103),
            [Operations] = ServiceUrl(configuration, "DOTNET_OPERATIONS_SERVICE_URL", "dotnet-operations-service", 5104),
            [Realtime] = ServiceUrl(configuration, "DOTNET_REALTIME_SERVICE_URL", "dotnet-realtime-service", 5105)
        };

    public static (IReadOnlyList<RouteConfig> Routes, IReadOnlyList<ClusterConfig> Clusters)
        BuildGatewayConfiguration(IConfiguration configuration)
    {
        var destinations = GatewayDestinations(configuration);
        var clusters = destinations.Select(pair => new ClusterConfig
        {
            ClusterId = pair.Key,
            Destinations = new Dictionary<string, DestinationConfig>
            {
                ["primary"] = new() { Address = EnsureTrailingSlash(pair.Value) }
            }
        }).ToArray();

        var routes = new List<RouteConfig>();
        AddRoutes(routes, Realtime, "/chatHub/{**catch-all}", "/api/chatHub/{**catch-all}");
        AddRoutes(routes, Auth,
            "/api/Auth/{**catch-all}",
            "/api/AccountManagement/{**catch-all}",
            "/api/password-reset-requests/{**catch-all}");
        AddRoutes(routes, Academic,
            "/api/Curriculums/{**catch-all}",
            "/api/GradeTemplate/{**catch-all}",
            "/api/Sectioning/{**catch-all}",
            "/api/RegistrarDashboard/{**catch-all}",
            "/api/registrar/Search/{**catch-all}");
        AddRoutes(routes, Grade,
            "/api/Grades/{**catch-all}",
            "/api/BulkUpload/{**catch-all}",
            "/api/Student/{**catch-all}");
        AddRoutes(routes, Operations,
            "/api/SystemSettings/{**catch-all}",
            "/api/SystemMonitoring/{**catch-all}",
            "/api/SupportTickets/{**catch-all}");

        return (routes, clusters);
    }

    private static IReadOnlySet<string> ControllerSet(params string[] names) =>
        new HashSet<string>(names, StringComparer.Ordinal);

    private static string ServiceUrl(IConfiguration configuration, string key, string host, int port)
    {
        var configured = configuration[key] ?? Environment.GetEnvironmentVariable(key);
        return string.IsNullOrWhiteSpace(configured)
            ? $"http://{host}.plv-fabric.svc.cluster.local:{port}"
            : configured.TrimEnd('/');
    }

    private static string EnsureTrailingSlash(string value) => $"{value.TrimEnd('/')}/";

    private static void AddRoutes(List<RouteConfig> routes, string cluster, params string[] paths)
    {
        for (var index = 0; index < paths.Length; index++)
        {
            routes.Add(new RouteConfig
            {
                RouteId = $"{cluster}-{index}",
                ClusterId = cluster,
                Match = new RouteMatch { Path = paths[index] }
            });
        }
    }
}
