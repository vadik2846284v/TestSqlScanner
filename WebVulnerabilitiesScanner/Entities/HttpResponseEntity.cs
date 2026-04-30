namespace WebVulnerabilitiesScanner.Entities
{
    /// <summary>
    /// Сущность ответа на http-запрос
    /// </summary>
    public class HttpResponseEntity
    {
        /// <summary>
        /// Тестовая ссылка
        /// </summary>
        public string UrlWithEndpoint
        {
            get
            {
                return BaseUrl + Endpoint;
            }
        }

        /// <summary>
        /// Адрес портала
        /// </summary>
        public string BaseUrl { get; set; }

        /// <summary>
        /// Эндпоинт
        /// </summary>
        public string Endpoint { get; set; }

        /// <summary>
        /// Нагрузка в запросе
        /// </summary>
        public string Payload { get; set; }

        /// <summary>
        /// Тип запроса
        /// </summary>
        public string RequestType { get; set; }

        /// <summary>
        /// Тело запроса (в случае POST-запроса)
        /// </summary>
        public string JsonBodyParams { get; set; }

        /// <summary>
        /// Тип SQL-инъекции
        /// </summary>
        public SqlInjectionType SqlInjectionType { get; set; }

        /// <summary>
        /// Рекомендация как исправить
        /// </summary>
        public string FixRecommendation { get; set; }

        /// <summary>
        /// Код ответа
        /// </summary>
        public System.Net.HttpStatusCode StatusCode { get; set; }

        /// <summary>
        /// Найдена ли SQL-инъекция
        /// </summary>
        public bool IsSqlVulnerable { get; set; }

        /// <summary>
        /// Не удалось ли выполнить проверку
        /// </summary>
        public bool IsExecutionFailed { get; set; }

        /// <summary>
        /// Признак SQL-инъекции
        /// </summary>
        public string SqlInjectionSign { get; set; }

        /// <summary>
        /// Длина запроса
        /// </summary>
        public int ResponseLength { get; set; }
    }
}
