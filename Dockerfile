# Build Stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy the C# project files and build
COPY . .

# Dynamically find the .csproj file and build it
RUN PROJECT_FILE=$(find . -name "*.csproj" | head -n 1) && \
    echo "Building project: $PROJECT_FILE" && \
    dotnet restore "$PROJECT_FILE" && \
    dotnet publish "$PROJECT_FILE" -c Release -o /app/publish

# Runtime Stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/publish .

# Expose port 5000 as expected by Kubernetes and Middleware
EXPOSE 5000
ENTRYPOINT ["dotnet", "For_Testing_Only_Capstone.dll"]