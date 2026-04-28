using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using WebVulnerabilitiesScanner.Entities;
using WebVulnerabilitiesScanner.TestData;
using static WebVulnerabilitiesScanner.TestData.SqlInjectionTestData;

/// <summary>
/// Сканнер SQL-инъекций
/// </summary>
public class SqlInjectionScanner
{
    private readonly string _baseUrl;

    private readonly HttpClient _httpClient;

    private readonly PortalType _portalType;

    public SqlInjectionScanner(string baseUrl, PortalType portalType)
    {
        _baseUrl = baseUrl;
        _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        _portalType = portalType;
    }

    /// <summary>
    /// Сканирование урла на наличие SQL-инъекций
    /// </summary>
    /// <returns></returns>
    public List<HttpResponseEntity> ScanForSqlInjection()
    {
        SqlInjectionTestData.GetTestDataByPortalType(_portalType, out List<string> getRequestsEndpoints, out List<PostRequestParams> postRequestsInfo);
        var results = new List<HttpResponseEntity>();
        // Boolean-based и time-based payload'ы обрабатываются отдельно, потому что требуют специальной логики проверки.
        var singleCheckPayloads = SqlInjectionTestData.BasePayloadsInfo.FindAll(payloadInfo =>
            payloadInfo.SqlInjectionType != SqlInjectionType.BooleanBased &&
            payloadInfo.SqlInjectionType != SqlInjectionType.TimeBasedBlind);

        foreach (var endpointInfo in getRequestsEndpoints)
        {
            foreach (var payloadInfo in singleCheckPayloads)
            {
                var result = TestGetRequest(endpointInfo, payloadInfo);
                results.Add(result.Result);
            }

            foreach (var payloadInfo in SqlInjectionTestData.TimeBasedBlindPayloadsInfo)
            {
                // Для time-based проверки отправляем несколько одинаковых запросов и считаем среднее время ответа.
                var result = TestTimeBasedGetRequest(endpointInfo, payloadInfo);
                results.Add(result.Result);
            }

            foreach (var booleanPayloadPair in SqlInjectionTestData.BooleanBasedPayloadPairs)
            {
                // Для слепой boolean-based проверки отправляем обе ветки: true и false.
                var result = TestBooleanBasedGetRequest(endpointInfo, booleanPayloadPair);
                results.Add(result.Result);
            }
        }

        foreach (var endpointInfo in postRequestsInfo) 
        {
            foreach (var payloadInfo in singleCheckPayloads)
            {
                var result = TestPostRequest(endpointInfo, payloadInfo);
                results.Add(result.Result);
            }

            foreach (var payloadInfo in SqlInjectionTestData.TimeBasedBlindPayloadsInfo)
            {
                // Для time-based проверки отправляем несколько одинаковых запросов и считаем среднее время ответа.
                var result = TestTimeBasedPostRequest(endpointInfo, payloadInfo);
                results.Add(result.Result);
            }

            foreach (var booleanPayloadPair in SqlInjectionTestData.BooleanBasedPayloadPairs)
            {
                // Для слепой boolean-based проверки отправляем обе ветки: true и false.
                var result = TestBooleanBasedPostRequest(endpointInfo, booleanPayloadPair);
                results.Add(result.Result);
            }
        }

        return results;
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
        catch (Exception)
        {
            throw;
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
        catch (Exception)
        {
            throw;
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
        catch (Exception)
        {
            throw;
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
    private async Task<HttpResponseEntity> TestPostRequest(PostRequestParams postRequestInfo, RequestSqlInjectionPayloadEntity payloadInfo) 
    {
        try 
        {
            var responseInfo = await ExecutePostRequest(postRequestInfo, payloadInfo.Payload);
            bool isSqlInjection = IsSqlInjectionExists(responseInfo.Content, responseInfo.StatusCode, responseInfo.ElapsedMilliseconds, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = postRequestInfo.Endpoint,
                Payload = payloadInfo.Payload,
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
        catch (Exception)
        {
            throw;
        }
    }

    /// <summary>
    /// Проверка POST-запроса на поиск time-based SQL-инъекции по усреднённому времени ответа.
    /// </summary>
    /// <param name="postRequestInfo">Инфомация для POST-запроса</param>
    /// <param name="payloadInfo">Информация о полезной нагрузке</param>
    /// <returns></returns>
    private async Task<HttpResponseEntity> TestTimeBasedPostRequest(PostRequestParams postRequestInfo, RequestSqlInjectionPayloadEntity payloadInfo)
    {
        try
        {
            var responseInfo = await ExecutePostRequestWithAverageTiming(postRequestInfo, payloadInfo.Payload, SqlInjectionTestData.TimeBasedBlindRequestsCountForAverage);
            bool isSqlInjection = IsTimeBasedSqlInjectionExists(responseInfo.ElapsedMilliseconds, responseInfo.MeasurementsCount, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = postRequestInfo.Endpoint,
                Payload = payloadInfo.Payload,
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
        catch (Exception)
        {
            throw;
        }
    }

    /// <summary>
    /// Проверка POST-запроса на поиск boolean-based SQL-инъекции по паре нагрузок.
    /// </summary>
    /// <param name="postRequestInfo">Инфомация для POST-запроса</param>
    /// <param name="payloadPair">Пара boolean-based нагрузок</param>
    /// <returns></returns>
    private async Task<HttpResponseEntity> TestBooleanBasedPostRequest(PostRequestParams postRequestInfo, BooleanBasedPayloadPairEntity payloadPair)
    {
        try
        {
            // Уязвимость подтверждается только если приложение по-разному отвечает на истинное и ложное условие.
            var trueResponseInfo = await ExecutePostRequest(postRequestInfo, payloadPair.TruePayloadInfo.Payload);
            var falseResponseInfo = await ExecutePostRequest(postRequestInfo, payloadPair.FalsePayloadInfo.Payload);
            bool isSqlInjection = IsBooleanBasedSqlInjectionExists(trueResponseInfo.Content, trueResponseInfo.StatusCode,
                falseResponseInfo.Content, falseResponseInfo.StatusCode, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = postRequestInfo.Endpoint,
                Payload = $"TRUE: {payloadPair.TruePayloadInfo.Payload}; FALSE: {payloadPair.FalsePayloadInfo.Payload}",
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
        catch (Exception)
        {
            throw;
        }
    }
    #endregion

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
    /// Выполнение POST-запроса с тестовой нагрузкой.
    /// </summary>
    /// <param name="postRequestInfo">Инфомация для POST-запроса</param>
    /// <param name="payload">Полезная нагрузка</param>
    /// <returns></returns>
    private async Task<(string Content, HttpStatusCode StatusCode, long ElapsedMilliseconds, string JsonBodyParams, int MeasurementsCount)> ExecutePostRequest(
        PostRequestParams postRequestInfo, string payload)
    {
        string testUrl = _baseUrl + postRequestInfo.Endpoint;

        var jsonPayload = new Dictionary<string, object>();
        foreach (var dataItem in postRequestInfo.BodyParams)
        {
            jsonPayload[dataItem.Key] = dataItem.Value;
        }

        foreach (var injectionField in postRequestInfo.BodyParams)
        {
            if (jsonPayload.ContainsKey(injectionField.Key))
            {
                jsonPayload[injectionField.Key] = payload;
            }
        }

        string jsonContent = JsonSerializer.Serialize(jsonPayload);
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
    /// <param name="payload">Полезная нагрузка</param>
    /// <param name="measurementsCount">Количество замеров</param>
    /// <returns></returns>
    private async Task<(string Content, HttpStatusCode StatusCode, long ElapsedMilliseconds, string JsonBodyParams, int MeasurementsCount)> ExecutePostRequestWithAverageTiming(
        PostRequestParams postRequestInfo, string payload, int measurementsCount)
    {
        long totalElapsedMilliseconds = 0;
        string content = string.Empty;
        string jsonBodyParams = string.Empty;
        HttpStatusCode statusCode = HttpStatusCode.OK;

        // Для time-based проверки усредняем несколько одинаковых запросов, чтобы снизить влияние сетевых задержек.
        for (int measurementIndex = 0; measurementIndex < measurementsCount; measurementIndex++)
        {
            var responseInfo = await ExecutePostRequest(postRequestInfo, payload);
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
            "foreign key constraint"
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

        // Сначала проверяем, что это вообще JSON
        if (!IsValidJson(content))
            return false;

        // Ключевые слова, указывающие на конфиденциальные данные
        var sensitiveKeywords = new List<string>
        {
            "user", "users", // пользователь
            "password", // пароль
            "email", "e-mail", // email
            "token", "access_token", "refresh_token", // токены
            "phone", "telephone", // телефон
            "address", // адрес
            "credit", // кредитная карта
            "ssn", // SSN
            "salary", // зарплата
            "birth", // дата рождения
            "id", // идентификатор
            "secret", // секрет
            "api_key", // API ключ
            "session", // сессия
            "auth", // аутентификация
            "role", // роль
            "permission", // разрешение
            "login" // логин
        };

        // Признаки JSON-структур с данными
        var jsonPatterns = new List<string>
        {
            "\"username\"", "\"password\"", "\"email\"",
            "\"first_name\"", "\"last_name\"", "\"full_name\"",
            "\"phone_number\"", "\"mobile\"",
            "\"address\"", "\"city\"", "\"zip\"", "\"country\"",
            "\"created_at\"", "\"updated_at\"", "\"last_login\"",
            "\"is_active\"", "\"is_admin\"", "\"permissions\"",
            "\"settings\"", "\"preferences\""
        };

        try
        {
            // Приводим к нижнему регистру для поиска
            string contentLower = content.ToLower();

            // Удаляем пробелы и переносы строк для более надежного поиска
            string compactContent = contentLower.Replace("\n", "").Replace("\r", "").Replace(" ", "");

            // Проверяем наличие JSON-паттернов
            foreach (var pattern in jsonPatterns)
            {
                if (compactContent.Contains(pattern.ToLower()))
                {
                    sqlInjectionSign = $"Вернувшийся контент имеет признак вернувшейся JSON-структуры с данными {pattern}";
                    return true;
                }
            }

            // Проверяем наличие ключевых слов в контексте JSON
            // Ищем паттерн: "keyword": (с любыми пробелами)
            foreach (var keyword in sensitiveKeywords)
            {
                // Проверяем несколько вариантов
                if (compactContent.Contains($"\"{keyword}\":") ||
                    compactContent.Contains($"{keyword}\":") ||
                    compactContent.Contains($"\"{keyword}\""))
                {
                    sqlInjectionSign = $"Вернувшийся контент имеет паттерн в виде 'keyword': 'значение' (keyword = {keyword})";
                    return true;
                }
            }
        }
        catch
        {
            // В случае ошибки парсинга считаем, что это не JSON
            return false;
        }

        return false;
    }

    /// <summary>
    /// Проверка валидности JSON
    /// </summary>
    /// <param name="strInput"></param>
    /// <returns></returns>
    private bool IsValidJson(string strInput)
    {
        if (string.IsNullOrWhiteSpace(strInput))
            return false;

        strInput = strInput.Trim();

        // Быстрая проверка по первым/последним символам
        if ((strInput.StartsWith("{") && strInput.EndsWith("}")) ||
            (strInput.StartsWith("[") && strInput.EndsWith("]")))
        {
            try
            {
                // Пытаемся парсить JSON
                using var doc = JsonDocument.Parse(strInput);
                return true;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        return false;
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
            case SqlInjectionType.ClassicSqlInjection:
                return "**Меры устранения:**\r\n" +
                    "1. Использовать параметризованные запросы (Prepared Statements)\r\n" +
                    "2. Валидация входных данных\r\n" +
                    "3. Использование хранимых процедур\r\n" +
                    "4. Принцип наименьших привилегий для БД";
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
