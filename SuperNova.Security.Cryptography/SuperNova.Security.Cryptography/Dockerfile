FROM microsoft/aspnetcore:2.0 AS base

RUN apt-get update -y

RUN  apt-get install openssl
WORKDIR /app

EXPOSE 80

FROM microsoft/aspnetcore-build:2.0 AS build
WORKDIR /src
COPY SuperNova.Security.Cryptography.sln ./
COPY SuperNova.Security.Cryptography/SuperNova.Security.Cryptography.csproj SuperNova.Security.Cryptography/
RUN dotnet restore -nowarn:msb3202,nu1503
COPY . .
WORKDIR /src/SuperNova.Security.Cryptography
RUN dotnet build -c Release -o /app

FROM build AS publish
RUN dotnet publish -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "SuperNova.Security.Cryptography.dll"]
