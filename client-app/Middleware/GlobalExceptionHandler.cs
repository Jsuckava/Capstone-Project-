using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Client_app.Middleware
{
    public class GlobalExceptionHandler : IExceptionHandler
    {
        private readonly ILogger<GlobalExceptionHandler> _logger;

        public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
        {
            _logger = logger;
        }

        public async ValueTask<bool> TryHandleAsync(
            HttpContext httpContext,
            Exception exception,
            CancellationToken cancellationToken)
        {
            var (statusCode, publicMessage, logAsError) = exception switch
            {
                UnauthorizedAccessException => (StatusCodes.Status403Forbidden, exception.Message, false),
                KeyNotFoundException => (StatusCodes.Status404NotFound, exception.Message, false),
                ArgumentException => (StatusCodes.Status400BadRequest, exception.Message, false),
                InvalidOperationException => (StatusCodes.Status409Conflict, exception.Message, false),
                _ => (StatusCodes.Status500InternalServerError, "An internal server error has occurred.", true)
            };

            if (logAsError) _logger.LogError(exception, "An unhandled exception occurred: {Message}", exception.Message);
            else _logger.LogWarning("Request rejected with {StatusCode}: {Message}", statusCode, exception.Message);

            var traceId = httpContext.TraceIdentifier;
            httpContext.Response.StatusCode = statusCode;
            await httpContext.Response.WriteAsJsonAsync(new { 
                status = "Error", 
                message = publicMessage,
                traceId = traceId
            }, cancellationToken);
            return true;
        }
    }
}
