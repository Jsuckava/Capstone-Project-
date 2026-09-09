using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.ApplicationParts;

namespace Client_app.Microservices;

/// <summary>
/// Removes controllers outside the bounded context hosted by the current
/// process. The same immutable image can therefore run every ASP.NET service,
/// matching the one-image/multiple-entrypoint model used by the Node middleware.
/// </summary>
public sealed class ServiceControllerFeatureProvider : IApplicationFeatureProvider<ControllerFeature>
{
    private readonly IReadOnlySet<string> _allowedControllers;

    public ServiceControllerFeatureProvider(IReadOnlySet<string> allowedControllers)
    {
        _allowedControllers = allowedControllers;
    }

    public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
    {
        for (var index = feature.Controllers.Count - 1; index >= 0; index--)
        {
            var fullName = feature.Controllers[index].FullName;
            if (string.IsNullOrWhiteSpace(fullName) || !_allowedControllers.Contains(fullName))
            {
                feature.Controllers.RemoveAt(index);
            }
        }
    }
}
