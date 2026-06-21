using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using WebVulnerabilitiesScanner.Entities;
using WebVulnerabilitiesScanner.Helpers;
using WebVulnerabilitiesScanner.TestData;

/// <summary>
/// Сканнер SQL-инъекций
/// </summary>
public class SqlInjectionScanner
{
    /// <summary>
    /// Минимальный таймаут HTTP-клиента в секундах для обычных запросов.
    /// </summary>
    private const int DefaultHttpClientTimeoutSeconds = 30;

    /// <summary>
    /// Дополнительный запас времени в секундах для time-based payload'ов.
    /// </summary>
    private const int TimeBasedTimeoutSafetyBufferSeconds = 3;

    /// <summary>
    /// Минимальное количество совпавших low-signal JSON-полей, необходимое для признания ответа чувствительным.
    /// </summary>
    private const int SensitiveJsonKeywordThreshold = 2;

    /// <summary>
    /// Базовый URL сканируемого приложения.
    /// </summary>
    private readonly string _baseUrl;

    /// <summary>
    /// HTTP-клиент, используемый для отправки тестовых запросов.
    /// </summary>
    private readonly HttpClient _httpClient;

    /// <summary>
    /// Имена JSON-полей с высоким сигналом, которые сами по себе считаются признаком чувствительных данных.
    /// </summary>
    private static readonly HashSet<string> HighSignalSensitiveJsonPropertyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "password",
        "username",
        "email",
        "access_token",
        "refresh_token",
        "api_key",
        "secret",
        "ssn",
        "phone_number",
        "mobile"
    };

    /// <summary>
    /// Имена JSON-полей со средним сигналом, которые считаются значимыми только при нескольких совпадениях.
    /// </summary>
    private static readonly HashSet<string> SensitiveJsonKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "user",
        "users",
        "username",
        "password",
        "email",
        "e-mail",
        "token",
        "access_token",
        "refresh_token",
        "phone",
        "telephone",
        "credit",
        "ssn",
        "salary",
        "birth",
        "secret",
        "api_key",
        "session",
        "auth",
        "permission"
    };

    public SqlInjectionScanner(string baseUrl)
    {
        _baseUrl = baseUrl;
        _httpClient = new HttpClient
        {
            // Таймаут должен покрывать серию замеров time-based payload'а с небольшим запасом.
            Timeout = CalculateHttpClientTimeout()
        };
    }

    /// <summary>
    /// Сканирование по явно переданным GET и POST запросам.
    /// </summary>
    /// <param name="getRequestsEndpoints">Эндпоинты GET-запросов</param>
    /// <param name="postRequestsInfo">Информация для POST-запросов</param>
    /// <returns>Результаты сканирования</returns>
    public List<HttpResponseEntity> ScanForSqlInjection(List<string> getRequestsEndpoints, List<PostRequestParams> postRequestsInfo)
    {
        var results = new List<HttpResponseEntity>();
        // Boolean-based и time-based payload'ы обрабатываются отдельно, потому что требуют специальной логики проверки.
        var singleCheckPayloads = SqlInjectionTestData.BasePayloadsInfo.FindAll(payloadInfo =>
            payloadInfo.SqlInjectionType != SqlInjectionType.BooleanBased &&
            payloadInfo.SqlInjectionType != SqlInjectionType.TimeBasedBlind);
        int checksPerEndpoint = singleCheckPayloads.Count
            + SqlInjectionTestData.TimeBasedBlindPayloadsInfo.Count
            + SqlInjectionTestData.BooleanBasedPayloadPairs.Count;
        int totalChecks = CalculateTotalChecks(getRequestsEndpoints.Count, postRequestsInfo, checksPerEndpoint);
        int currentCheck = 0;

        if (totalChecks == 0)
        {
            ConsoleHelper.WriteNoChecksMessage();
            return results;
        }

        ConsoleHelper.WriteScanStart(totalChecks);

        foreach (var endpointInfo in getRequestsEndpoints)
        {
            foreach (var payloadInfo in singleCheckPayloads)
            {
                ConsoleHelper.WriteScanProgress(++currentCheck, totalChecks, "GET", endpointInfo, payloadInfo.Payload);
                var result = TestGetRequest(endpointInfo, payloadInfo);
                results.Add(result.GetAwaiter().GetResult());
            }

            foreach (var payloadInfo in SqlInjectionTestData.TimeBasedBlindPayloadsInfo)
            {
                // Для time-based проверки отправляем несколько одинаковых запросов и считаем среднее время ответа.
                ConsoleHelper.WriteScanProgress(++currentCheck, totalChecks, "GET", endpointInfo, payloadInfo.Payload);
                var result = TestTimeBasedGetRequest(endpointInfo, payloadInfo);
                results.Add(result.GetAwaiter().GetResult());
            }

            foreach (var booleanPayloadPair in SqlInjectionTestData.BooleanBasedPayloadPairs)
            {
                // Для слепой boolean-based проверки отправляем обе ветки: true и false.
                string payloadDescription = BuildBooleanPayloadDescription(booleanPayloadPair);
                ConsoleHelper.WriteScanProgress(++currentCheck, totalChecks, "GET", endpointInfo, payloadDescription);
                var result = TestBooleanBasedGetRequest(endpointInfo, booleanPayloadPair);
                results.Add(result.GetAwaiter().GetResult());
            }
        }

        foreach (var endpointInfo in postRequestsInfo) 
        {
            foreach (var bodyFieldName in GetPostBodyFieldNames(endpointInfo))
            {
                foreach (var payloadInfo in singleCheckPayloads)
                {
                    string payloadDescription = BuildPostPayloadDescription(bodyFieldName, payloadInfo.Payload);
                    ConsoleHelper.WriteScanProgress(++currentCheck, totalChecks, "POST", endpointInfo.Endpoint, payloadDescription);
                    var result = TestPostRequest(endpointInfo, bodyFieldName, payloadInfo);
                    results.Add(result.GetAwaiter().GetResult());
                }

                foreach (var payloadInfo in SqlInjectionTestData.TimeBasedBlindPayloadsInfo)
                {
                    // Для time-based проверки отправляем несколько одинаковых запросов и считаем среднее время ответа.
                    string payloadDescription = BuildPostPayloadDescription(bodyFieldName, payloadInfo.Payload);
                    ConsoleHelper.WriteScanProgress(++currentCheck, totalChecks, "POST", endpointInfo.Endpoint, payloadDescription);
                    var result = TestTimeBasedPostRequest(endpointInfo, bodyFieldName, payloadInfo);
                    results.Add(result.GetAwaiter().GetResult());
                }

                foreach (var booleanPayloadPair in SqlInjectionTestData.BooleanBasedPayloadPairs)
                {
                    // Для слепой boolean-based проверки отправляем обе ветки: true и false.
                    string payloadDescription = BuildPostPayloadDescription(bodyFieldName, BuildBooleanPayloadDescription(booleanPayloadPair));
                    ConsoleHelper.WriteScanProgress(++currentCheck, totalChecks, "POST", endpointInfo.Endpoint, payloadDescription);
                    var result = TestBooleanBasedPostRequest(endpointInfo, bodyFieldName, booleanPayloadPair);
                    results.Add(result.GetAwaiter().GetResult());
                }
            }
        }

        return results;
    }

    /// <summary>
    /// Вычисляет общее количество логических проверок для всех GET- и POST-эндпоинтов.
    /// </summary>
    /// <param name="getEndpointsCount">Количество GET-эндпоинтов.</param>
    /// <param name="postRequestsInfo">POST-эндпоинты с параметрами body.</param>
    /// <param name="checksPerEndpoint">Количество проверок, выполняемых для одного GET-эндпоинта или одного поля POST-body.</param>
    /// <returns>Общее количество проверок для всего сканирования.</returns>
    private static int CalculateTotalChecks(
        int getEndpointsCount,
        IEnumerable<PostRequestParams> postRequestsInfo,
        int checksPerEndpoint)
    {
        int getChecksCount = getEndpointsCount * checksPerEndpoint;
        int postChecksCount = postRequestsInfo.Sum(postRequestInfo => GetPostBodyFieldNames(postRequestInfo).Count * checksPerEndpoint);
        return getChecksCount + postChecksCount;
    }

    /// <summary>
    /// Вычисляет таймаут HttpClient с учётом длительности одного time-based payload'а.
    /// </summary>
    /// <returns>Таймаут, достаточный для выполнения одного самого долгого time-based запроса с запасом.</returns>
    private static TimeSpan CalculateHttpClientTimeout()
    {
        int recommendedTimeoutSeconds =
            SqlInjectionTestData.TimeValueForTimeBasedBlind_s + TimeBasedTimeoutSafetyBufferSeconds;

        int timeoutSeconds = Math.Max(DefaultHttpClientTimeoutSeconds, recommendedTimeoutSeconds);
        return TimeSpan.FromSeconds(timeoutSeconds);
    }

    /// <summary>
    /// Формирует строковое описание пары boolean-based payload'ов для вывода в прогрессе и отчёте об ошибке.
    /// </summary>
    /// <param name="payloadPair">Пара payload'ов для истинной и ложной ветки boolean-based проверки.</param>
    /// <returns>Строка с описанием TRUE и FALSE payload'ов.</returns>
    private static string BuildBooleanPayloadDescription(BooleanBasedPayloadPairEntity payloadPair)
    {
        return $"TRUE: {payloadPair.TruePayloadInfo.Payload}; FALSE: {payloadPair.FalsePayloadInfo.Payload}";
    }

    /// <summary>
    /// Возвращает имена полей тела POST-запроса, которые нужно проверять по одному.
    /// </summary>
    /// <param name="postRequestInfo">Информация о POST-запросе.</param>
    /// <returns>Список имён полей для последовательного тестирования.</returns>
    private static List<string> GetPostBodyFieldNames(PostRequestParams postRequestInfo)
    {
        return postRequestInfo.BodyParams.Keys.ToList();
    }

    /// <summary>
    /// Формирует строковое описание payload'а для POST-проверки конкретного поля body.
    /// </summary>
    /// <param name="bodyFieldName">Имя тестируемого поля.</param>
    /// <param name="payloadDescription">Описание payload'а.</param>
    /// <returns>Строка для прогресса и отчёта.</returns>
    private static string BuildPostPayloadDescription(string bodyFieldName, string payloadDescription)
    {
        return $"field '{bodyFieldName}' | {payloadDescription}";
    }

    #region GET Methods tests
    /// <summary>
    /// Проверка GET-запроса на поиск SQL-инъекции 
    /// </summary>
    /// <param name="endpoint">Эндпоинт</param>
    /// <param name="payloadInfo">Информация о полезной нагрузке</param>
    /// <returns></returns>
    private async Task<HttpResponseEntity> TestGetRequest(string endpoint, RequestSqlInjectionPayloadEntity payloadInfo)
    {
        try
        {
            var responseInfo = await ExecuteGetRequest(endpoint, payloadInfo.Payload);
            bool isSqlInjection = IsSqlInjectionExists(responseInfo.Content, responseInfo.StatusCode, responseInfo.ElapsedMilliseconds,
                out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = endpoint,
                Payload = payloadInfo.Payload,
                RequestType = "GET",
                SqlInjectionType = payloadInfo.SqlInjectionType,
                FixRecommendation = GetRecommendationForSqlInjection(payloadInfo.SqlInjectionType),
                StatusCode = responseInfo.StatusCode,
                IsSqlVulnerable = isSqlInjection,
                SqlInjectionSign = sqlInjectionSign,
                ResponseLength = responseInfo.Content.Length
            };
        }
        catch (Exception ex)
        {
            return CreateFailedResponseEntity(endpoint, "GET", payloadInfo.Payload, payloadInfo.SqlInjectionType, ex);
        }
    }

    /// <summary>
    /// Проверка GET-запроса на поиск boolean-based SQL-инъекции по паре нагрузок.
    /// </summary>
    /// <param name="endpoint">Эндпоинт</param>
    /// <param name="payloadPair">Пара boolean-based нагрузок</param>
    /// <returns></returns>
    private async Task<HttpResponseEntity> TestBooleanBasedGetRequest(string endpoint, BooleanBasedPayloadPairEntity payloadPair)
    {
        try
        {
            // Уязвимость подтверждается только если приложение по-разному отвечает на истинное и ложное условие.
            var trueResponseInfo = await ExecuteGetRequest(endpoint, payloadPair.TruePayloadInfo.Payload);
            var falseResponseInfo = await ExecuteGetRequest(endpoint, payloadPair.FalsePayloadInfo.Payload);
            bool isSqlInjection = IsBooleanBasedSqlInjectionExists(trueResponseInfo.Content, trueResponseInfo.StatusCode,
                falseResponseInfo.Content, falseResponseInfo.StatusCode, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = endpoint,
                Payload = $"TRUE: {payloadPair.TruePayloadInfo.Payload}; FALSE: {payloadPair.FalsePayloadInfo.Payload}",
                RequestType = "GET",
                SqlInjectionType = SqlInjectionType.BooleanBased,
                FixRecommendation = GetRecommendationForSqlInjection(SqlInjectionType.BooleanBased),
                StatusCode = trueResponseInfo.StatusCode,
                IsSqlVulnerable = isSqlInjection,
                SqlInjectionSign = sqlInjectionSign,
                ResponseLength = trueResponseInfo.Content.Length
            };
        }
        catch (Exception ex)
        {
            string payloadDescription = $"TRUE: {payloadPair.TruePayloadInfo.Payload}; FALSE: {payloadPair.FalsePayloadInfo.Payload}";
            return CreateFailedResponseEntity(endpoint, "GET", payloadDescription, SqlInjectionType.BooleanBased, ex);
        }
    }

    /// <summary>
    /// Проверка GET-запроса на поиск time-based SQL-инъекции по усреднённому времени ответа.
    /// </summary>
    /// <param name="endpoint">Эндпоинт</param>
    /// <param name="payloadInfo">Информация о полезной нагрузке</param>
    /// <returns></returns>
    private async Task<HttpResponseEntity> TestTimeBasedGetRequest(string endpoint, RequestSqlInjectionPayloadEntity payloadInfo)
    {
        try
        {
            var responseInfo = await ExecuteGetRequestWithAverageTiming(endpoint, payloadInfo.Payload, SqlInjectionTestData.TimeBasedBlindRequestsCountForAverage);
            bool isSqlInjection = IsTimeBasedSqlInjectionExists(responseInfo.ElapsedMilliseconds, responseInfo.MeasurementsCount, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = endpoint,
                Payload = payloadInfo.Payload,
                RequestType = "GET",
                SqlInjectionType = payloadInfo.SqlInjectionType,
                FixRecommendation = GetRecommendationForSqlInjection(payloadInfo.SqlInjectionType),
                StatusCode = responseInfo.StatusCode,
                IsSqlVulnerable = isSqlInjection,
                SqlInjectionSign = sqlInjectionSign,
                ResponseLength = responseInfo.Content.Length
            };
        }
        catch (Exception ex)
        {
            return CreateFailedResponseEntity(endpoint, "GET", payloadInfo.Payload, payloadInfo.SqlInjectionType, ex);
        }
    }
    #endregion

    #region POST Methods tests
    /// <summary>
    /// Проверка POST-запроса на поиск SQL-инъекции
    /// </summary>
    /// <param name="postRequestInfo">Инфомация для POST-запроса</param>
    /// <param name="payloadInfo">Полезная нагрузка</param>
    /// <returns></returns>
    private async Task<HttpResponseEntity> TestPostRequest(
        PostRequestParams postRequestInfo,
        string bodyFieldName,
        RequestSqlInjectionPayloadEntity payloadInfo) 
    {
        string payloadDescription = BuildPostPayloadDescription(bodyFieldName, payloadInfo.Payload);
        string jsonBodyParams = BuildPostJsonBody(postRequestInfo, bodyFieldName, payloadInfo.Payload);

        try 
        {
            var responseInfo = await ExecutePostRequest(postRequestInfo, bodyFieldName, payloadInfo.Payload);
            bool isSqlInjection = IsSqlInjectionExists(responseInfo.Content, responseInfo.StatusCode, responseInfo.ElapsedMilliseconds, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = postRequestInfo.Endpoint,
                Payload = payloadDescription,
                RequestType = "POST",
                JsonBodyParams = responseInfo.JsonBodyParams,
                SqlInjectionType = payloadInfo.SqlInjectionType,
                FixRecommendation = GetRecommendationForSqlInjection(payloadInfo.SqlInjectionType),
                StatusCode = responseInfo.StatusCode,
                IsSqlVulnerable = isSqlInjection,
                SqlInjectionSign = sqlInjectionSign,
                ResponseLength = responseInfo.Content.Length
            };
        } 
        catch (Exception ex)
        {
            return CreateFailedResponseEntity(
                postRequestInfo.Endpoint,
                "POST",
                payloadDescription,
                payloadInfo.SqlInjectionType,
                ex,
                jsonBodyParams);
        }
    }

    /// <summary>
    /// Проверка POST-запроса на поиск time-based SQL-инъекции по усреднённому времени ответа.
    /// </summary>
    /// <param name="postRequestInfo">Инфомация для POST-запроса</param>
    /// <param name="payloadInfo">Информация о полезной нагрузке</param>
    /// <returns></returns>
    private async Task<HttpResponseEntity> TestTimeBasedPostRequest(
        PostRequestParams postRequestInfo,
        string bodyFieldName,
        RequestSqlInjectionPayloadEntity payloadInfo)
    {
        string payloadDescription = BuildPostPayloadDescription(bodyFieldName, payloadInfo.Payload);
        string jsonBodyParams = BuildPostJsonBody(postRequestInfo, bodyFieldName, payloadInfo.Payload);

        try
        {
            var responseInfo = await ExecutePostRequestWithAverageTiming(
                postRequestInfo,
                bodyFieldName,
                payloadInfo.Payload,
                SqlInjectionTestData.TimeBasedBlindRequestsCountForAverage);
            bool isSqlInjection = IsTimeBasedSqlInjectionExists(responseInfo.ElapsedMilliseconds, responseInfo.MeasurementsCount, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = postRequestInfo.Endpoint,
                Payload = payloadDescription,
                RequestType = "POST",
                JsonBodyParams = responseInfo.JsonBodyParams,
                SqlInjectionType = payloadInfo.SqlInjectionType,
                FixRecommendation = GetRecommendationForSqlInjection(payloadInfo.SqlInjectionType),
                StatusCode = responseInfo.StatusCode,
                IsSqlVulnerable = isSqlInjection,
                SqlInjectionSign = sqlInjectionSign,
                ResponseLength = responseInfo.Content.Length
            };
        }
        catch (Exception ex)
        {
            return CreateFailedResponseEntity(
                postRequestInfo.Endpoint,
                "POST",
                payloadDescription,
                payloadInfo.SqlInjectionType,
                ex,
                jsonBodyParams);
        }
    }

    /// <summary>
    /// Проверка POST-запроса на поиск boolean-based SQL-инъекции по паре нагрузок.
    /// </summary>
    /// <param name="postRequestInfo">Инфомация для POST-запроса</param>
    /// <param name="payloadPair">Пара boolean-based нагрузок</param>
    /// <returns></returns>
    private async Task<HttpResponseEntity> TestBooleanBasedPostRequest(
        PostRequestParams postRequestInfo,
        string bodyFieldName,
        BooleanBasedPayloadPairEntity payloadPair)
    {
        string booleanPayloadDescription = BuildBooleanPayloadDescription(payloadPair);
        string payloadDescription = BuildPostPayloadDescription(bodyFieldName, booleanPayloadDescription);
        string truePayloadJsonBody = BuildPostJsonBody(postRequestInfo, bodyFieldName, payloadPair.TruePayloadInfo.Payload);
        string falsePayloadJsonBody = BuildPostJsonBody(postRequestInfo, bodyFieldName, payloadPair.FalsePayloadInfo.Payload);

        try
        {
            // Уязвимость подтверждается только если приложение по-разному отвечает на истинное и ложное условие.
            var trueResponseInfo = await ExecutePostRequest(postRequestInfo, bodyFieldName, payloadPair.TruePayloadInfo.Payload);
            var falseResponseInfo = await ExecutePostRequest(postRequestInfo, bodyFieldName, payloadPair.FalsePayloadInfo.Payload);
            bool isSqlInjection = IsBooleanBasedSqlInjectionExists(trueResponseInfo.Content, trueResponseInfo.StatusCode,
                falseResponseInfo.Content, falseResponseInfo.StatusCode, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = postRequestInfo.Endpoint,
                Payload = payloadDescription,
                RequestType = "POST",
                JsonBodyParams = $"TRUE payload body: {trueResponseInfo.JsonBodyParams}{Environment.NewLine}FALSE payload body: {falseResponseInfo.JsonBodyParams}",
                SqlInjectionType = SqlInjectionType.BooleanBased,
                FixRecommendation = GetRecommendationForSqlInjection(SqlInjectionType.BooleanBased),
                StatusCode = trueResponseInfo.StatusCode,
                IsSqlVulnerable = isSqlInjection,
                SqlInjectionSign = sqlInjectionSign,
                ResponseLength = trueResponseInfo.Content.Length
            };
        }
        catch (Exception ex)
        {
            string failedJsonBodyParams =
                $"TRUE payload body: {truePayloadJsonBody}{Environment.NewLine}FALSE payload body: {falsePayloadJsonBody}";
            return CreateFailedResponseEntity(
                postRequestInfo.Endpoint,
                "POST",
                payloadDescription,
                SqlInjectionType.BooleanBased,
                ex,
                failedJsonBodyParams);
        }
    }
    #endregion

    /// <summary>
    /// Создание результата неуспешной проверки, чтобы отразить ошибку в отчёте и продолжить сканирование.
    /// </summary>
    /// <param name="endpoint">Эндпоинт, на котором произошла ошибка</param>
    /// <param name="requestType">Тип HTTP-запроса</param>
    /// <param name="payload">Payload, использованный в проверке</param>
    /// <param name="sqlInjectionType">Тип проверяемой SQL-инъекции</param>
    /// <param name="exception">Исключение, возникшее при выполнении проверки</param>
    /// <param name="jsonBodyParams">Тело POST-запроса, если оно было подготовлено.</param>
    /// <returns>Сущность результата с признаком ошибки выполнения</returns>
    private HttpResponseEntity CreateFailedResponseEntity(
        string endpoint,
        string requestType,
        string payload,
        SqlInjectionType sqlInjectionType,
        Exception exception,
        string jsonBodyParams = "")
    {
        LogScanError(requestType, endpoint, payload, exception);

        return new HttpResponseEntity
        {
            BaseUrl = _baseUrl,
            Endpoint = endpoint,
            Payload = payload,
            RequestType = requestType,
            JsonBodyParams = jsonBodyParams,
            SqlInjectionType = sqlInjectionType,
            FixRecommendation = GetRecommendationForSqlInjection(sqlInjectionType),
            StatusCode = 0,
            IsSqlVulnerable = false,
            IsExecutionFailed = true,
            SqlInjectionSign = $"Проверка не выполнена: {exception.Message}",
            ResponseLength = 0
        };
    }

    /// <summary>
    /// Логирование ошибки выполнения отдельной проверки без остановки всего сканирования.
    /// </summary>
    /// <param name="requestType">Тип HTTP-запроса</param>
    /// <param name="endpoint">Эндпоинт, на котором произошла ошибка</param>
    /// <param name="payload">Payload, использованный в проверке</param>
    /// <param name="exception">Исключение, возникшее при выполнении проверки</param>
    private void LogScanError(string requestType, string endpoint, string payload, Exception exception)
    {
        Console.WriteLine(
            $"[Scanner error] Не удалось выполнить {requestType}-проверку для эндпоинта '{endpoint}' с payload '{payload}': {exception.Message}");
    }

    #region Execute requests
    /// <summary>
    /// Выполнение GET-запроса с тестовой нагрузкой.
    /// </summary>
    /// <param name="endpoint">Эндпоинт</param>
    /// <param name="payload">Полезная нагрузка</param>
    /// <returns></returns>
    private async Task<(string Content, HttpStatusCode StatusCode, long ElapsedMilliseconds, int MeasurementsCount)> ExecuteGetRequest(string endpoint, string payload)
    {
        string encodedPayload = Uri.EscapeDataString(payload);
        var testUrl = _baseUrl + endpoint + encodedPayload;

        var stopwatch = Stopwatch.StartNew();
        var response = await _httpClient.GetAsync(testUrl);
        stopwatch.Stop();

        var content = await response.Content.ReadAsStringAsync();
        return (content, response.StatusCode, stopwatch.ElapsedMilliseconds, 1);
    }

    /// <summary>
    /// Выполнение GET-запроса несколько раз для расчёта среднего времени ответа.
    /// </summary>
    /// <param name="endpoint">Эндпоинт</param>
    /// <param name="payload">Полезная нагрузка</param>
    /// <param name="measurementsCount">Количество замеров</param>
    /// <returns></returns>
    private async Task<(string Content, HttpStatusCode StatusCode, long ElapsedMilliseconds, int MeasurementsCount)> ExecuteGetRequestWithAverageTiming(
        string endpoint, string payload, int measurementsCount)
    {
        long totalElapsedMilliseconds = 0;
        string content = string.Empty;
        HttpStatusCode statusCode = HttpStatusCode.OK;

        // Для time-based проверки усредняем несколько одинаковых запросов, чтобы снизить влияние сетевых задержек.
        for (int measurementIndex = 0; measurementIndex < measurementsCount; measurementIndex++)
        {
            var responseInfo = await ExecuteGetRequest(endpoint, payload);
            totalElapsedMilliseconds += responseInfo.ElapsedMilliseconds;
            content = responseInfo.Content;
            statusCode = responseInfo.StatusCode;
        }

        long averageElapsedMilliseconds = (long)Math.Round((double)totalElapsedMilliseconds / measurementsCount);
        return (content, statusCode, averageElapsedMilliseconds, measurementsCount);
    }

    /// <summary>
    /// Формирует JSON-тело POST-запроса с подстановкой payload только в одно указанное поле.
    /// </summary>
    /// <param name="postRequestInfo">Информация о POST-запросе.</param>
    /// <param name="bodyFieldName">Поле body, в которое подставляется payload.</param>
    /// <param name="payload">Тестовая нагрузка.</param>
    /// <returns>Сериализованное JSON-тело запроса.</returns>
    private static string BuildPostJsonBody(PostRequestParams postRequestInfo, string bodyFieldName, string payload)
    {
        var jsonPayload = new Dictionary<string, object>();
        foreach (var dataItem in postRequestInfo.BodyParams)
        {
            jsonPayload[dataItem.Key] = dataItem.Value;
        }

        if (!jsonPayload.ContainsKey(bodyFieldName))
            throw new InvalidOperationException($"Поле '{bodyFieldName}' отсутствует в body для POST endpoint '{postRequestInfo.Endpoint}'.");

        jsonPayload[bodyFieldName] = payload;
        return JsonSerializer.Serialize(jsonPayload);
    }

    /// <summary>
    /// Выполнение POST-запроса с тестовой нагрузкой.
    /// </summary>
    /// <param name="postRequestInfo">Инфомация для POST-запроса</param>
    /// <param name="bodyFieldName">Имя поля body, в которое подставляется payload.</param>
    /// <param name="payload">Полезная нагрузка</param>
    /// <returns></returns>
    private async Task<(string Content, HttpStatusCode StatusCode, long ElapsedMilliseconds, string JsonBodyParams, int MeasurementsCount)> ExecutePostRequest(
        PostRequestParams postRequestInfo, string bodyFieldName, string payload)
    {
        string testUrl = _baseUrl + postRequestInfo.Endpoint;
        string jsonContent = BuildPostJsonBody(postRequestInfo, bodyFieldName, payload);
        var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");

        var stopwatch = Stopwatch.StartNew();
        var response = await _httpClient.PostAsync(testUrl, httpContent);
        stopwatch.Stop();

        var content = await response.Content.ReadAsStringAsync();
        return (content, response.StatusCode, stopwatch.ElapsedMilliseconds, jsonContent, 1);
    }

    /// <summary>
    /// Выполнение POST-запроса несколько раз для расчёта среднего времени ответа.
    /// </summary>
    /// <param name="postRequestInfo">Инфомация для POST-запроса</param>
    /// <param name="bodyFieldName">Имя поля body, в которое подставляется payload.</param>
    /// <param name="payload">Полезная нагрузка</param>
    /// <param name="measurementsCount">Количество замеров</param>
    /// <returns></returns>
    private async Task<(string Content, HttpStatusCode StatusCode, long ElapsedMilliseconds, string JsonBodyParams, int MeasurementsCount)> ExecutePostRequestWithAverageTiming(
        PostRequestParams postRequestInfo, string bodyFieldName, string payload, int measurementsCount)
    {
        long totalElapsedMilliseconds = 0;
        string content = string.Empty;
        string jsonBodyParams = string.Empty;
        HttpStatusCode statusCode = HttpStatusCode.OK;

        // Для time-based проверки усредняем несколько одинаковых запросов, чтобы снизить влияние сетевых задержек.
        for (int measurementIndex = 0; measurementIndex < measurementsCount; measurementIndex++)
        {
            var responseInfo = await ExecutePostRequest(postRequestInfo, bodyFieldName, payload);
            totalElapsedMilliseconds += responseInfo.ElapsedMilliseconds;
            content = responseInfo.Content;
            jsonBodyParams = responseInfo.JsonBodyParams;
            statusCode = responseInfo.StatusCode;
        }

        long averageElapsedMilliseconds = (long)Math.Round((double)totalElapsedMilliseconds / measurementsCount);
        return (content, statusCode, averageElapsedMilliseconds, jsonBodyParams, measurementsCount);
    }
    #endregion

    #region Validation and recommendation methods
    /// <summary>
    /// Проверка, нашли ли SQL-инъекцию после запроса
    /// </summary>
    /// <param name="content">Вернувшийся контент после выполнения запроса</param>
    /// <param name="httpStatusCode">Код http запроса</param>
    /// <param name="requestTime_ms">Время выполнения запроса (в мс)</param>
    /// <param name="sqlInjectionSign">Текстовый признак обнаружения sql-инъекции</param>
    /// <returns></returns>
    private bool IsSqlInjectionExists(string content, HttpStatusCode httpStatusCode, long requestTime_ms, out string sqlInjectionSign)
    {
        // Признаки возможной SQL-инъекции
        var sqlErrors = new List<string>
        {
            "sql syntax",
            "mysql_fetch",
            "ora-",
            "microsoft odbc",
            "postgresql",
            "sqlite_exception",
            "warning: mysql",
            "unclosed quotation mark",
            "syntax error",
            "you have an error in your sql",
            "supplied argument is not a valid",
            "invalid query",
            "sqlite3",
            "pgsql",
            "mysql error",
            "sql server",
            "violation of",
            "foreign key constraint",
            "xpath syntax error",
        };

        // Проверка на ошибки СУБД в ответе
        foreach (var error in sqlErrors)
        {
            if (content.ToLower().Contains(error))
            {
                sqlInjectionSign = $"В контенте при выполнении запроса вернулась ошибка: {error}";
                return true;
            }
        }

        // Проверка на наличие JSON-данных (например, информация о пользователе)
        if (HasSensitiveJsonData(content, out string sensitiveJsonDateSign))
        {
            sqlInjectionSign = sensitiveJsonDateSign;
            return true;
        }

        sqlInjectionSign = string.Empty;
        return false;
    }

    /// <summary>
    /// Проверка, нашли ли time-based SQL-инъекцию по усреднённому времени ответа.
    /// </summary>
    /// <param name="requestTime_ms">Время выполнения запроса (в мс)</param>
    /// <param name="measurementsCount">Количество измерений времени выполнения запроса</param>
    /// <param name="sqlInjectionSign">Текстовый признак обнаружения sql-инъекции</param>
    /// <returns>Возвращает true, если обнаружена time-based SQL-инъекция, иначе false</returns>
    bool IsTimeBasedSqlInjectionExists(long requestTime_ms, int measurementsCount, out string sqlInjectionSign)
    {
        if (requestTime_ms >= SqlInjectionTestData.TimeValueForTimeBasedBlind_s * 1000 - 1000)
        {
            sqlInjectionSign = $"Среднее время выполнения {measurementsCount} sql-запросов слишком большое ({requestTime_ms} мс)";
            return true;
        }
        sqlInjectionSign = string.Empty;
        return false;
    }

    /// <summary>
    /// Проверка, нашли ли boolean-based SQL-инъекцию по различию ответов на true/false payload'ы.
    /// </summary>
    /// <param name="trueContent">Контент ответа на true payload</param>
    /// <param name="trueStatusCode">Код ответа на true payload</param>
    /// <param name="falseContent">Контент ответа на false payload</param>
    /// <param name="falseStatusCode">Код ответа на false payload</param>
    /// <param name="sqlInjectionSign">Текстовый признак обнаружения sql-инъекции</param>
    /// <returns></returns>
    private bool IsBooleanBasedSqlInjectionExists(string trueContent, HttpStatusCode trueStatusCode,
        string falseContent, HttpStatusCode falseStatusCode, out string sqlInjectionSign)
    {
        var signs = new List<string>();

        // Разные статусы часто означают, что SQL-условие меняет серверную ветку выполнения.
        if (trueStatusCode != falseStatusCode)
        {
            signs.Add($"коды ответа отличаются: TRUE={trueStatusCode}, FALSE={falseStatusCode}");
        }

        // Даже при одинаковом статусе различие тела ответа указывает на boolean-based поведение.
        if (!string.Equals(trueContent, falseContent, StringComparison.Ordinal))
        {
            if (trueContent.Length != falseContent.Length)
            {
                signs.Add($"длина ответов отличается: TRUE={trueContent.Length}, FALSE={falseContent.Length}");
            }
            else
            {
                signs.Add("тело ответов отличается при одинаковой длине");
            }
        }

        if (signs.Count > 0)
        {
            sqlInjectionSign = $"Boolean-based проверка подтвердилась: ответы на TRUE/FALSE payload различаются ({string.Join("; ", signs)})";
            return true;
        }

        sqlInjectionSign = string.Empty;
        return false;
    }

    /// <summary>
    /// Проверка наличия конфиденциальных JSON-данных
    /// </summary>
    /// <param name="content">обрабатываемый JSON-ответ</param>
    /// <param name="sqlInjectionSign">Признак SQL инъекции</param>
    /// <returns></returns>
    private bool HasSensitiveJsonData(string content, out string sqlInjectionSign)
    {
        sqlInjectionSign = string.Empty;

        if (string.IsNullOrWhiteSpace(content))
            return false;

        if (!TryCollectJsonPropertyNames(content, out var jsonPropertyNames))
            return false;

        string? highSignalPropertyName = jsonPropertyNames
            .FirstOrDefault(propertyName => HighSignalSensitiveJsonPropertyNames.Contains(propertyName));

        if (!string.IsNullOrWhiteSpace(highSignalPropertyName))
        {
            sqlInjectionSign = $"Вернувшийся контент содержит чувствительное JSON-поле '{highSignalPropertyName}'";
            return true;
        }

        var matchedSensitiveKeywords = jsonPropertyNames
            .Where(propertyName => SensitiveJsonKeywords.Contains(propertyName))
            .OrderBy(propertyName => propertyName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (matchedSensitiveKeywords.Count >= SensitiveJsonKeywordThreshold)
        {
            sqlInjectionSign =
                $"Вернувшийся контент содержит несколько чувствительных JSON-полей: {string.Join(", ", matchedSensitiveKeywords)}";
            return true;
        }

        return false;
    }

    /// <summary>
    /// Пытается извлечь все имена полей из JSON-документа для последующей проверки на чувствительные данные.
    /// </summary>
    /// <param name="content">Исходный JSON-контент.</param>
    /// <param name="propertyNames">Набор имён JSON-полей, найденных в документе.</param>
    /// <returns>True, если контент является валидным JSON; иначе false.</returns>
    private static bool TryCollectJsonPropertyNames(string content, out HashSet<string> propertyNames)
    {
        propertyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(content))
            return false;

        string trimmedContent = content.Trim();

        if (!((trimmedContent.StartsWith("{") && trimmedContent.EndsWith("}")) ||
            (trimmedContent.StartsWith("[") && trimmedContent.EndsWith("]"))))
        {
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(trimmedContent);
            CollectJsonPropertyNames(doc.RootElement, propertyNames);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Рекурсивно обходит JSON-элемент и добавляет имена всех вложенных полей в результирующий набор.
    /// </summary>
    /// <param name="element">Текущий JSON-элемент.</param>
    /// <param name="propertyNames">Набор для накопления найденных имён полей.</param>
    private static void CollectJsonPropertyNames(JsonElement element, HashSet<string> propertyNames)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    propertyNames.Add(property.Name);
                    CollectJsonPropertyNames(property.Value, propertyNames);
                }
                break;
            case JsonValueKind.Array:
                foreach (var arrayItem in element.EnumerateArray())
                {
                    CollectJsonPropertyNames(arrayItem, propertyNames);
                }
                break;
        }
    }

    /// <summary>
    /// Получение рекомендации к устранению SQL-инъекции конкретного типа
    /// </summary>
    /// <param name="sqlInjectionType">Тип SQL-инъекции</param>
    /// <returns></returns>
    public string GetRecommendationForSqlInjection(SqlInjectionType sqlInjectionType)
    {
        switch (sqlInjectionType)
        {
            case SqlInjectionType.UnionBased:
                return "**Меры устранения:**\r\n" +
                    "1. Валидация типа данных для числовых параметров\r\n" +
                    "2. Использование белых списков для имён таблиц/столбцов\r\n" +
                    "3. Ограничение прав пользователя БД только на чтение необходимых таблиц\r\n" +
                    "4. Логирование попыток UNION инъекций";
            case SqlInjectionType.ErrorBased:
                return "**Меры устранения:**\r\n" +
                    "1. Настройка кастомных страниц ошибок\r\n" +
                    "2. Отключение детальных SQL ошибок в production\r\n" +
                    "3. Использование централизованного логирования ошибок\r\n" +
                    "4. Блокировка повторных запросов с SQL ошибками";
            case SqlInjectionType.TimeBasedBlind:
                return "**Меры устранения:**\r\n" +
                    "1. Установка таймаутов на запросы к БД\r\n" +
                    "2. Мониторинг длительных SQL запросов\r\n" +
                    "3. Использование rate limiting\r\n" +
                    "4. Внедрение WAF с защитой от time-based атак";
            case SqlInjectionType.BooleanBased:
                return "**Меры устранения:**\r\n" +
                    "1. Унификация ответов (одинаковые ответы при успехе/неудаче)\r\n" +
                    "2. Использование капчи при множественных запросах\r\n" +
                    "3. Мониторинг аномальных паттернов запросов";
            case SqlInjectionType.StackedQueries:
                return "**Меры устранения:**\r\n" +
                    "1. Запрет множественных запросов (MultipleActiveResultSets=false)\r\n" +
                    "2. Использование пользователя БД с минимальными правами\r\n" +
                    "3. Регулярное резервное копирование\r\n" +
                    "4. Аудит DDL команд";
            default:
                return string.Empty;
        }
    }
    #endregion
}
