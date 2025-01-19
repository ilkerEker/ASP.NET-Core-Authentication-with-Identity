namespace DotnetAuth.Domain.Contracts
{
    public class ErrorResponse
    {
        public string Titnet { get; set; }
        public int StatusCode { get; set; }
        public string Message { get; set; }
    }
}
