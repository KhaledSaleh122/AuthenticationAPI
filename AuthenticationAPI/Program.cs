using AuthenticationAPI;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();

builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(k =>
{
    k.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    k.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(p =>
{
    var key = Encoding.UTF8.GetBytes(builder.Configuration["JWTToken:Key"]);
    p.SaveToken = true;
    p.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["JWTToken:Issuer"],
        ValidAudience = builder.Configuration["JWTToken:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

//builder.Services.AddScoped<IJWTTokenServices, JWTServiceManage>();

var app = builder.Build();





if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}


app.MapGet("/auth", () =>
{
    const string username = "x";
    const string password = "y";
    var generater = new JwtTokenGenerator(builder.Configuration);

    return generater.GenerateToken(username, password);
});

app.MapGet("/valid", (string token) =>
{
    var generater = new JwtTokenGenerator(builder.Configuration);
    return generater.ValidateToken(token);
});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/whome", (HttpContext httpContext) =>
{
    var claims = httpContext.User.Claims;
    foreach (var claim in claims) { 
        Console.WriteLine(claim.Type+ " "+claim.Value);
    }
}).RequireAuthorization();

app.Run();
