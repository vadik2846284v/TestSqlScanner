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
    /// <param name="baseUrl">Адрес портала</param>
    /// <returns></returns>
    public List<HttpResponseEntity> ScanForSqlInjection()
    {
        SqlInjectionTestData.GetTestDataByPortalType(_portalType, out List<string> getRequestsEndpoints, out List<PostRequestParams> postRequestsInfo);
        var results = new List<HttpResponseEntity>();

        foreach (var endpointInfo in getRequestsEndpoints)
        {
            foreach (var payloadInfo in SqlInjectionTestData.BasePayloadsInfo)
            {
                var result = TestGetRequest(endpointInfo, payloadInfo);
                results.Add(result.Result);
            }
        }

        foreach (var endpointInfo in postRequestsInfo) 
        {
            foreach (var payloadInfo in SqlInjectionTestData.BasePayloadsInfo)
            {
                var result = TestPostRequest(endpointInfo, payloadInfo);
                results.Add(result.Result);
            }
        }

        return results;
    }

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
            string encodedPayload = Uri.EscapeDataString(payloadInfo.Payload);
            var testUrl = _baseUrl + endpoint + encodedPayload;

            // Выполняем GET-запрос
            var stopwatch = Stopwatch.StartNew();
            var response = await _httpClient.GetAsync(testUrl);
            stopwatch.Stop();

            // Читаем содержимое ответа
            var content = await response.Content.ReadAsStringAsync();
            var statusCode = response.StatusCode;
            bool isSqlInjection = IsSqlInjectionExists(content, statusCode, stopwatch.ElapsedMilliseconds, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = endpoint,
                Payload = payloadInfo.Payload,
                RequestType = "GET",
                SqlInjectionType = payloadInfo.SqlInjectionType,
                FixRecommendation = GetRecommendationForSqlInjection(payloadInfo.SqlInjectionType),
                StatusCode = statusCode,
                IsSqlVulnerable = isSqlInjection,
                SqlInjectionSign = sqlInjectionSign,
                ResponseLength = content.Length
            };
        }
        catch (Exception)
        {
            throw;
        }
    }

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
            string testUrl = _baseUrl + postRequestInfo.Endpoint;

            // Для JSON сериализуем полезную нагрузку как JSON
            var jsonPayload = new Dictionary<string, object>();

            foreach (var dataItem in postRequestInfo.BodyParams)
            {
                jsonPayload[dataItem.Key] = dataItem.Value;
            }

            // Добавляем полезную нагрузку SQL-инъекции
            foreach (var injectionField in postRequestInfo.BodyParams)
            {
                if (jsonPayload.ContainsKey(injectionField.Key))
                {
                    jsonPayload[injectionField.Key] = payloadInfo.Payload;
                }
            }
            string jsonContent = JsonSerializer.Serialize(jsonPayload);
            var httpContent = new StringContent(jsonContent, Encoding.UTF8, "application/json");

            // Выполняем POST-запрос
            var stopwatch = Stopwatch.StartNew();
            var response = await _httpClient.PostAsync(testUrl, httpContent);
            stopwatch.Stop();

            var content = await response.Content.ReadAsStringAsync();
            var statusCode = response.StatusCode;
            bool isSqlInjection = IsSqlInjectionExists(content, statusCode, stopwatch.ElapsedMilliseconds, out string sqlInjectionSign);

            return new HttpResponseEntity
            {
                BaseUrl = _baseUrl,
                Endpoint = postRequestInfo.Endpoint,
                Payload = payloadInfo.Payload,
                RequestType = "POST",
                JsonBodyParams = jsonContent,
                SqlInjectionType = payloadInfo.SqlInjectionType,
                FixRecommendation = GetRecommendationForSqlInjection(payloadInfo.SqlInjectionType),
                StatusCode = statusCode,
                IsSqlVulnerable = isSqlInjection,
                SqlInjectionSign = sqlInjectionSign,
                ResponseLength = content.Length
            };
        } 
        catch (Exception)
        {
            throw;
        }
    }

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

        if (requestTime_ms >= SqlInjectionTestData.TimeValueForTimeBasedBlind_s * 1000 - 1000) 
        {
            sqlInjectionSign = $"Слишком большое время выполнения sql-запроса ({requestTime_ms})";
            return true;
        }

        // Необычные коды статусов
        if (httpStatusCode != HttpStatusCode.OK) 
        {
            sqlInjectionSign = $"В результате выполнения запроса вернулся необычный код {httpStatusCode}";
            return true;
        }

        // Проверка на наличие JSON-данных (например, информация о пользователе)
        if (HasSensitiveJsonData(content, out string sensitiveJsonDateSign))
        {
            sqlInjectionSign = sensitiveJsonDateSign;
            return true;
        }

        // Необычно длинные или короткие ответы
        if (content.Length < 50 || content.Length > 10000) 
        {
            sqlInjectionSign = $"Вернулся контент необычной длины: {content.Length}";
            return true;
        }

        sqlInjectionSign = default;
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
        sqlInjectionSign = default;

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
}
