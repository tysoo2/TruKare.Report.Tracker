using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using TruKare.Reports.Desktop.Models;

namespace TruKare.Reports.Desktop.Api;

public class ReportApiClient
{
    private readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web);

    public async Task<IReadOnlyList<ReportDto>> SearchReportsAsync(string apiBase, SearchReportsRequestDto request, CancellationToken cancellationToken)
    {
        using var httpClient = CreateClient(apiBase);
        var query = BuildQueryString(request);
        var response = await httpClient.GetAsync($"/reports{query}", cancellationToken);
        await EnsureSuccessAsync(response);
        var payload = await response.Content.ReadFromJsonAsync<List<ReportDto>>(_serializerOptions, cancellationToken);
        return payload ?? Array.Empty<ReportDto>();
    }

    public async Task<ReportStatusResponseDto> GetStatusAsync(string apiBase, Guid reportId, CancellationToken cancellationToken)
    {
        using var httpClient = CreateClient(apiBase);
        var response = await httpClient.GetAsync($"/reports/{reportId}/status", cancellationToken);
        await EnsureSuccessAsync(response);
        var payload = await response.Content.ReadFromJsonAsync<ReportStatusResponseDto>(_serializerOptions, cancellationToken);
        if (payload == null)
        {
            throw new InvalidOperationException("Unable to read status payload.");
        }

        return payload;
    }

    public async Task<CheckoutResponseDto> CheckoutAsync(string apiBase, CheckoutRequestDto request, CancellationToken cancellationToken)
    {
        using var httpClient = CreateClient(apiBase);
        var response = await httpClient.PostAsJsonAsync("/reports/checkout", request, _serializerOptions, cancellationToken);
        await EnsureSuccessAsync(response);
        var payload = await response.Content.ReadFromJsonAsync<CheckoutResponseDto>(_serializerOptions, cancellationToken);
        if (payload == null)
        {
            throw new InvalidOperationException("Unable to read checkout response.");
        }

        return payload;
    }

    public async Task CheckinAsync(string apiBase, CheckinRequestDto request, CancellationToken cancellationToken)
    {
        using var httpClient = CreateClient(apiBase);
        var response = await httpClient.PostAsJsonAsync("/reports/checkin", request, _serializerOptions, cancellationToken);
        await EnsureSuccessAsync(response);
    }

    private static HttpClient CreateClient(string apiBase)
    {
        if (string.IsNullOrWhiteSpace(apiBase))
        {
            throw new InvalidOperationException("API base address is required.");
        }

        return new HttpClient
        {
            BaseAddress = new Uri(apiBase.TrimEnd('/'))
        };
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync();
        var message = string.IsNullOrWhiteSpace(body)
            ? response.ReasonPhrase
            : body;
        throw new InvalidOperationException($"API call failed ({response.StatusCode}): {message}");
    }

    private static string BuildQueryString(SearchReportsRequestDto request)
    {
        var builder = new StringBuilder("?");
        void Append(string name, string value)
        {
            if (builder.Length > 1)
            {
                builder.Append('&');
            }

            builder.Append(name);
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(value));
        }

        if (!string.IsNullOrWhiteSpace(request.CustomerName))
        {
            Append("customerName", request.CustomerName);
        }

        if (!string.IsNullOrWhiteSpace(request.UnitNumber))
        {
            Append("unitNumber", request.UnitNumber);
        }

        if (!string.IsNullOrWhiteSpace(request.ReportType))
        {
            Append("reportType", request.ReportType);
        }

        Append("includeArchived", request.IncludeArchived.ToString());
        return builder.Length > 1 ? builder.ToString() : string.Empty;
    }
}
