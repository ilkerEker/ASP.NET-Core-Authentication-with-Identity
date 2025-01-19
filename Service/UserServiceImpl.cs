using AutoMapper;
using DotnetAuth.Domain.Contracts;
using DotnetAuth.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace DotnetAuth.Service
{
    public class UserServiceImpl : IUserServices
    {
        private readonly ITokenService _tokenService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ICurrentUserService _currentUserService;
        private readonly IMapper _mapper;
    private readonly ILogger<UserServiceImpl> _logger;

        public UserServiceImpl(ITokenService tokenService, UserManager<ApplicationUser> userManager, ICurrentUserService currentUserService, IMapper mapper, ILogger<UserServiceImpl> logger)
        {
            _tokenService = tokenService;
            _userManager = userManager;
            _currentUserService = currentUserService;
            _mapper = mapper;
            _logger = logger;
        }

        public Task DeleteAsync(Guid id)
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> GetByIdAsync(Guid id)
        {
            throw new NotImplementedException();
        }

        public Task<CurrentUserResponse> GetCurrentUserAsync()
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> LoginAsync(UserLoginRequest request)
        {
            throw new NotImplementedException();
        }

        public Task<CurrentUserResponse> RefreshTokenAsync(RefreshTokenRequest request)
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> RegisterAsync(UserRegisterRequest request)
        {
            throw new NotImplementedException();
        }

        public Task<RevokeRefreshTokenResponse> RevokeRefreshToken(RefreshTokenRequest refreshTokenRemoveRequest)
        {
            throw new NotImplementedException();
        }

        public Task<UserResponse> UpdateAsync(Guid id, UpdateUserRequest request)
        {
            throw new NotImplementedException();
        }
    }
}
