# Build Stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Restore dependencies from the project definition so source-only changes can
# reuse Docker's NuGet cache layer.
COPY *.csproj ./
RUN --mount=type=cache,id=blockgo-nuget,target=/root/.nuget/packages \
    dotnet restore For_Testing_Only_Capstone.csproj --disable-parallel

# Publish the application
COPY . .
RUN --mount=type=cache,id=blockgo-nuget,target=/root/.nuget/packages \
    dotnet publish For_Testing_Only_Capstone.csproj -c Release -o /app/publish --no-restore

# Runtime Stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# The shared image runs as the gateway or one bounded service, selected through
# DOTNET_SERVICE_NAME and DOTNET_SERVICE_PORT by the deployment manifest.
EXPOSE 5000 5101 5102 5103 5104 5105
ENV ASPNETCORE_URLS=http://+:5000

# Start the application
ENTRYPOINT ["dotnet", "For_Testing_Only_Capstone.dll"]
