using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.Helpers
{
    /// <summary>
    /// Выполняет ИИ-анализ результатов сканирования через GigaChat API.
    /// </summary>
    public sealed class GigaChatScanAnalysisService
    {
        private const string OAuthTokenUrl = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth";
        private const string ChatCompletionsUrl = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions";
        private const string DefaultScope = "GIGACHAT_API_PERS";
        private const string DefaultModel = "GigaChat-2-Pro";
        private const int MaxPromptFindingCount = 50;
        private const int MaxPromptFieldLength = 220;

        private readonly HttpClient? _httpClient;
        private readonly bool _isEnabled;
        private readonly string? _authorizationKey;
        private readonly string _model;
        private readonly string _scope;
        private readonly bool _allowInsecureSsl;

        /// <summary>
        /// Инициализирует сервис анализа с параметрами из JSON-конфигурации.
        /// </summary>
        /// <param name="configuration">Настройки GigaChat из отдельного JSON-конфига.</param>
        public GigaChatScanAnalysisService(GigaChatConfiguration? configuration)
        {
            _isEnabled = configuration is not null;
            _authorizationKey = ReadOptionalConfigurationValue(configuration?.AuthorizationKey);
            _model = ReadConfigurationOrDefault(configuration?.Model, DefaultModel);
            _scope = ReadConfigurationOrDefault(configuration?.Scope, DefaultScope);
            _allowInsecureSsl = configuration?.AllowInsecureSsl == true;
            _httpClient = _isEnabled ? CreateHttpClient() : null;
        }

        /// <summary>
        /// Запускает ИИ-анализ результатов сканирования и возвращает итоговый статус.
        /// </summary>
        /// <param name="baseUrl">Базовый адрес сканируемого приложения.</param>
        /// <param name="configurationName">Название конфигурации сканирования.</param>
        /// <param name="results">Результаты выполненных проверок.</param>
        /// <returns>Результат выполнения ИИ-анализа.</returns>
        public async Task<AiScanAnalysisResult> AnalyzeResultsAsync(
            string baseUrl,
            string configurationName,
            IReadOnlyCollection<HttpResponseEntity> results)
        {
            if (!_isEnabled)
            {
                return new AiScanAnalysisResult
                {
                    StatusMessage = "ИИ-анализ пропущен: отдельный конфиг GigaChat не задан или отключён."
                };
            }

            if (string.IsNullOrWhiteSpace(_authorizationKey))
            {
                return new AiScanAnalysisResult
                {
                    StatusMessage = "ИИ-анализ пропущен: в конфиге GigaChat не заполнено поле authorizationKey."
                };
            }

            if (results.Count == 0)
            {
                return new AiScanAnalysisResult
                {
                    StatusMessage = "ИИ-анализ пропущен: нет результатов сканирования для обработки."
                };
            }

            var vulnerableResults = results.Where(result => result.IsSqlVulnerable).ToList();
            if (vulnerableResults.Count == 0)
            {
                return new AiScanAnalysisResult
                {
                    StatusMessage = "ИИ-анализ пропущен: нет запросов с обнаруженной уязвимостью для передачи в GigaChat."
                };
            }

            try
            {
                string accessToken = await GetAccessTokenAsync();
                string prompt = BuildAnalysisPrompt(baseUrl, configurationName, vulnerableResults);
                string analysisSummary = await RequestAnalysisSummaryAsync(accessToken, prompt);

                return new AiScanAnalysisResult
                {
                    IsGenerated = true,
                    Summary = analysisSummary.Trim(),
                    StatusMessage = $"ИИ-анализ успешно получен через GigaChat ({_model})."
                };
            }
            catch (Exception ex)
            {
                return new AiScanAnalysisResult
                {
                    IsFailed = true,
                    StatusMessage = $"ИИ-анализ через GigaChat завершился ошибкой: {BuildFriendlyErrorMessage(ex)}"
                };
            }
        }

        /// <summary>
        /// Создаёт HttpClient для обращения к GigaChat API с учётом настроек TLS.
        /// </summary>
        /// <returns>Настроенный экземпляр HttpClient.</returns>
        private HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler();

            if (_allowInsecureSsl)
            {
                handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
            return new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMinutes(2)
            };
        }

        /// <summary>
        /// Получает OAuth-токен для дальнейших запросов к GigaChat API.
        /// </summary>
        /// <returns>Токен доступа GigaChat API.</returns>
        private async Task<string> GetAccessTokenAsync()
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, OAuthTokenUrl);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Add("RqUID", Guid.NewGuid().ToString());
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", NormalizeAuthorizationKey(_authorizationKey!));
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["scope"] = _scope
            });

            using var response = await _httpClient!.SendAsync(request);
            string responseContent = await response.Content.ReadAsStringAsync();
            response.EnsureSuccessStatusCode();

            using var jsonDocument = JsonDocument.Parse(responseContent);
            if (!jsonDocument.RootElement.TryGetProperty("access_token", out var accessTokenElement))
                throw new InvalidOperationException("GigaChat не вернул access_token.");

            string? accessToken = accessTokenElement.GetString();
            if (string.IsNullOrWhiteSpace(accessToken))
                throw new InvalidOperationException("GigaChat вернул пустой access_token.");

            return accessToken;
        }

        /// <summary>
        /// Отправляет в GigaChat сводку по уязвимым запросам и получает текст анализа.
        /// </summary>
        /// <param name="accessToken">OAuth-токен GigaChat.</param>
        /// <param name="prompt">Подготовленный prompt с уязвимыми запросами.</param>
        /// <returns>Текст ИИ-анализа.</returns>
        private async Task<string> RequestAnalysisSummaryAsync(string accessToken, string prompt)
        {
            var payload = new
            {
                model = _model,
                messages = new object[]
                {
                    new
                    {
                        role = "system",
                        content = "Ты анализируешь только те запросы сканера SQL-инъекций, по которым уже выставлен флаг обнаруженной уязвимости. Для каждого запроса кратко опиши, какие признаки или ошибки указывают на возможную SQL-инъекцию. Не придумывай факты и опирайся только на переданную сводку."
                    },
                    new
                    {
                        role = "user",
                        content = prompt
                    }
                },
                stream = false,
                max_tokens = 1200
            };

            using var request = new HttpRequestMessage(HttpMethod.Post, ChatCompletionsUrl);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Content = JsonContent.Create(payload);

            using var response = await _httpClient!.SendAsync(request);
            string responseContent = await response.Content.ReadAsStringAsync();
            response.EnsureSuccessStatusCode();

            using var jsonDocument = JsonDocument.Parse(responseContent);
            if (!jsonDocument.RootElement.TryGetProperty("choices", out var choicesElement) ||
                choicesElement.ValueKind != JsonValueKind.Array ||
                choicesElement.GetArrayLength() == 0)
            {
                throw new InvalidOperationException("GigaChat не вернул choices в ответе chat/completions.");
            }

            JsonElement firstChoice = choicesElement[0];
            if (!firstChoice.TryGetProperty("message", out var messageElement) ||
                !messageElement.TryGetProperty("content", out var contentElement))
            {
                throw new InvalidOperationException("GigaChat не вернул message.content в ответе chat/completions.");
            }

            string? content = contentElement.GetString();
            if (string.IsNullOrWhiteSpace(content))
                throw new InvalidOperationException("GigaChat вернул пустой текст анализа.");

            return content;
        }

        /// <summary>
        /// Собирает компактную текстовую сводку только по запросам с найденной уязвимостью.
        /// </summary>
        /// <param name="baseUrl">Базовый адрес сканируемого приложения.</param>
        /// <param name="configurationName">Название конфигурации сканирования.</param>
        /// <param name="results">Только запросы с флагом уязвимости.</param>
        /// <returns>Подготовленный prompt для ИИ-модели.</returns>
        private static string BuildAnalysisPrompt(
            string baseUrl,
            string configurationName,
            IReadOnlyCollection<HttpResponseEntity> results)
        {
            var distribution = results
                .GroupBy(result => result.SqlInjectionType)
                .OrderByDescending(group => group.Count())
                .Select(group => $"- {group.Key}: {group.Count()}")
                .ToList();

            var promptBuilder = new StringBuilder();
            promptBuilder.AppendLine("Ниже перечислены только те запросы, по которым сканер уже отметил возможную SQL-инъекцию.");
            promptBuilder.AppendLine("Проанализируй каждый запрос отдельно и ответь на русском языке.");
            promptBuilder.AppendLine("Для каждого запроса укажи:");
            promptBuilder.AppendLine("1. Какой запрос был выполнен.");
            promptBuilder.AppendLine("2. Какая нагрузка была передана в запрос.");
            promptBuilder.AppendLine("3. Какой признак или ошибка указывает на возможную SQL-инъекцию.");
            promptBuilder.AppendLine("4. Почему это выглядит подозрительно.");
            promptBuilder.AppendLine("5. Что стоит перепроверить вручную.");
            promptBuilder.AppendLine();
            promptBuilder.AppendLine("Контекст:");
            promptBuilder.AppendLine($"- Конфигурация: {configurationName}");
            promptBuilder.AppendLine($"- Базовый URL: {baseUrl}");
            promptBuilder.AppendLine($"- Количество запросов с флагом уязвимости: {results.Count}");
            promptBuilder.AppendLine();
            promptBuilder.AppendLine("Распределение по типам уязвимостей:");

            foreach (string distributionItem in distribution)
            {
                promptBuilder.AppendLine(distributionItem);
            }

            promptBuilder.AppendLine();
            promptBuilder.AppendLine("Запросы с обнаруженной уязвимостью:");
            foreach (var result in results.Take(MaxPromptFindingCount))
            {
                promptBuilder.AppendLine($"- {BuildResultSummary(result)}");
            }

            promptBuilder.AppendLine();
            promptBuilder.AppendLine("Не анализируй безопасные или завершившиеся ошибкой проверки, которых нет в списке. Сфокусируйся только на переданных запросах с флагом уязвимости и на том, какие признаки указывают на проблему.");
            return promptBuilder.ToString();
        }

        /// <summary>
        /// Преобразует отдельный результат сканирования в компактную строку для prompt.
        /// </summary>
        /// <param name="result">Результат одной проверки.</param>
        /// <returns>Краткое описание результата.</returns>
        private static string BuildResultSummary(HttpResponseEntity result)
        {
            return $"{result.RequestType} {ShortenForPrompt(result.Endpoint)} | " +
                $"{result.SqlInjectionType} | status={(result.IsExecutionFailed ? "FAILED" : result.StatusCode.ToString())} | " +
                $"payload={ShortenForPrompt(result.Payload)} | sign={ShortenForPrompt(result.SqlInjectionSign)} | " +
                $"body={ShortenForPrompt(result.JsonBodyParams)}";
        }

        /// <summary>
        /// Нормализует строку авторизации для заголовка Basic.
        /// </summary>
        /// <param name="authorizationKey">Исходное значение из JSON-конфигурации.</param>
        /// <returns>Только значение токена без префикса Basic.</returns>
        private static string NormalizeAuthorizationKey(string authorizationKey)
        {
            const string basicPrefix = "Basic ";
            if (authorizationKey.StartsWith(basicPrefix, StringComparison.OrdinalIgnoreCase))
                return authorizationKey[basicPrefix.Length..].Trim();

            return authorizationKey.Trim();
        }

        /// <summary>
        /// Возвращает значение из конфигурации или подставляет значение по умолчанию.
        /// </summary>
        /// <param name="configurationValue">Значение из JSON-конфигурации.</param>
        /// <param name="defaultValue">Запасное значение.</param>
        /// <returns>Обрезанное значение из конфигурации либо defaultValue.</returns>
        private static string ReadConfigurationOrDefault(string? configurationValue, string defaultValue)
        {
            return string.IsNullOrWhiteSpace(configurationValue) ? defaultValue : configurationValue.Trim();
        }

        /// <summary>
        /// Возвращает необязательное значение из конфигурации либо null.
        /// </summary>
        /// <param name="configurationValue">Значение из JSON-конфигурации.</param>
        /// <returns>Обрезанное значение из конфигурации либо null.</returns>
        private static string? ReadOptionalConfigurationValue(string? configurationValue)
        {
            return string.IsNullOrWhiteSpace(configurationValue) ? null : configurationValue.Trim();
        }

        /// <summary>
        /// Сокращает длинное поле перед отправкой в prompt, чтобы не раздувать контекст модели.
        /// </summary>
        /// <param name="value">Исходное значение поля.</param>
        /// <returns>Сокращённый текст.</returns>
        private static string ShortenForPrompt(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            string normalizedValue = value.Replace(Environment.NewLine, " ").Trim();
            if (normalizedValue.Length <= MaxPromptFieldLength)
                return normalizedValue;

            return normalizedValue[..(MaxPromptFieldLength - 3)] + "...";
        }

        /// <summary>
        /// Формирует более полезное сообщение об ошибке для пользователя.
        /// </summary>
        /// <param name="exception">Исключение, полученное при обращении к GigaChat.</param>
        /// <returns>Подготовленный текст ошибки.</returns>
        private static string BuildFriendlyErrorMessage(Exception exception)
        {
            string fullMessage = exception.ToString();
            if (fullMessage.Contains("certificate", StringComparison.OrdinalIgnoreCase) ||
                fullMessage.Contains("ssl", StringComparison.OrdinalIgnoreCase) ||
                fullMessage.Contains("tls", StringComparison.OrdinalIgnoreCase))
            {
                return "ошибка TLS/сертификата при обращении к GigaChat API. " +
                    "Укажите в конфиге GigaChat поле caCertificatePath с сертификатом НУЦ Минцифры " +
                    "или, только для локальной отладки, включите allowInsecureSsl=true.";
            }

            return exception.Message;
        }
    }
}
