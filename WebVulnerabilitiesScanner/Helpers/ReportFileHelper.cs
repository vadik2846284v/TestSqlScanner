using System.Net;
using Scriban;
using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.Helpers
{
    /// <summary>
    /// Сохранение результатов сканирования в HTML-отчёт.
    /// </summary>
    public static class ReportFileHelper
    {
        private static readonly string ReportTemplateRelativePath = Path.Combine("Templates", "ScanReportTemplate.html");

        /// <summary>
        /// Сохранение результатов сканирования в html-файл.
        /// </summary>
        /// <param name="baseUrl">Базовый адрес сканируемого портала</param>
        /// <param name="portalTypeDescription">Описание типа портала</param>
        /// <param name="results">Результаты сканирования</param>
        /// <returns>Полный путь к сохранённому файлу отчёта</returns>
        public static string SaveScanReport(string baseUrl, string portalTypeDescription, List<HttpResponseEntity> results)
        {
            var reportsDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Reports");
            Directory.CreateDirectory(reportsDirectory);

            var generatedAt = DateTime.Now;
            var reportFileName = $"ScanReport_{generatedAt:yyyyMMdd_HHmmss}.html";
            var reportFilePath = Path.Combine(reportsDirectory, reportFileName);
            var failedResults = results.FindAll(result => result.IsExecutionFailed);
            var vulnerableResults = results.FindAll(result => result.IsSqlVulnerable);

            // Шаблон хранится отдельно от C#-кода, чтобы HTML-отчёт было проще поддерживать и расширять.
            string reportTemplate = File.ReadAllText(GetReportTemplatePath());
            var template = Template.Parse(reportTemplate);
            if (template.HasErrors)
                throw new InvalidOperationException($"Не удалось разобрать шаблон HTML-отчёта: {template.Messages}");

            // Сначала собираем безопасную модель данных, затем передаём её в шаблонизатор.
            var reportModel = BuildReportModel(baseUrl, portalTypeDescription, results, failedResults, vulnerableResults, generatedAt);
            string htmlReport = template.Render(reportModel, member => member.Name);

            File.WriteAllText(reportFilePath, htmlReport);
            return reportFilePath;
        }

        /// <summary>
        /// Получение абсолютного пути к HTML-шаблону отчёта.
        /// </summary>
        /// <returns>Полный путь к файлу шаблона</returns>
        private static string GetReportTemplatePath()
        {
            string templatePath = Path.Combine(AppContext.BaseDirectory, ReportTemplateRelativePath);
            if (!File.Exists(templatePath))
                throw new FileNotFoundException($"Не найден шаблон HTML-отчёта: {templatePath}");

            return templatePath;
        }

        /// <summary>
        /// Построение модели данных, которая будет передана в шаблон отчёта.
        /// </summary>
        /// <param name="baseUrl">Базовый адрес сканируемого портала</param>
        /// <param name="portalTypeDescription">Описание типа портала</param>
        /// <param name="results">Полный набор результатов сканирования</param>
        /// <param name="vulnerableResults">Только уязвимые результаты</param>
        /// <param name="generatedAt">Дата и время генерации отчёта</param>
        /// <returns>Готовая модель для рендера HTML-отчёта</returns>
        private static ReportTemplateModel BuildReportModel(
            string baseUrl,
            string portalTypeDescription,
            List<HttpResponseEntity> results,
            List<HttpResponseEntity> failedResults,
            List<HttpResponseEntity> vulnerableResults,
            DateTime generatedAt)
        {
            var safeResults = results.FindAll(result => !result.IsSqlVulnerable && !result.IsExecutionFailed);

            return new ReportTemplateModel
            {
                GeneratedAt = HtmlEncode(generatedAt.ToString("dd.MM.yyyy HH:mm:ss")),
                PortalTypeDescription = HtmlEncode(portalTypeDescription),
                BaseUrl = HtmlEncode(baseUrl),
                TotalChecks = results.Count,
                VulnerableChecks = vulnerableResults.Count,
                FailedChecks = failedResults.Count,
                SafeChecks = safeResults.Count,
                VulnerablePercent = GetVulnerablePercent(results.Count, vulnerableResults.Count).ToString("0.##"),
                Distribution = vulnerableResults
                    .GroupBy(result => result.SqlInjectionType)
                    .Select(group => new DistributionItemTemplateModel
                    {
                        SqlInjectionType = HtmlEncode(group.Key.ToString()),
                        Count = group.Count()
                    })
                    .ToList(),
                Vulnerabilities = vulnerableResults
                    .Select((result, index) => BuildVulnerabilityTemplateModel(result, index + 1))
                    .ToList(),
                FailedChecksDetails = failedResults
                    .Select((result, index) => BuildFailedCheckTemplateModel(result, index + 1))
                    .ToList(),
                Checks = results
                    .Select(BuildCheckTemplateModel)
                    .ToList()
            };
        }

        /// <summary>
        /// Преобразование одного найденного срабатывания в модель для блока детализации.
        /// </summary>
        /// <param name="result">Результат проверки</param>
        /// <param name="index">Порядковый номер результата в отчёте</param>
        /// <returns>Модель найденной уязвимости для шаблона</returns>
        private static VulnerabilityTemplateModel BuildVulnerabilityTemplateModel(HttpResponseEntity result, int index)
        {
            var details = new List<DetailsItemTemplateModel>
            {
                CreateDetailsItem("Полный адрес", result.UrlWithEndpoint),
                CreateDetailsItem("Payload", result.Payload),
                CreateDetailsItem("Тип запроса", result.RequestType),
                CreateDetailsItem("Статус ответа", result.StatusCode.ToString()),
                CreateDetailsItem("Тип SQL-инъекции", result.SqlInjectionType.ToString()),
                CreateDetailsItem("Признак обнаружения", result.SqlInjectionSign)
            };

            if (result.RequestType == "POST")
                details.Add(CreateDetailsItem("Тело запроса", result.JsonBodyParams));

            details.Add(CreateDetailsItem("Рекомендация к исправлению", result.FixRecommendation));

            return new VulnerabilityTemplateModel
            {
                Index = index,
                SqlInjectionType = HtmlEncode(result.SqlInjectionType.ToString()),
                RequestType = HtmlEncode(result.RequestType),
                Endpoint = HtmlEncode(result.Endpoint),
                Details = details
            };
        }

        /// <summary>
        /// Преобразование результата проверки в строку общей таблицы отчёта.
        /// </summary>
        /// <param name="result">Результат проверки</param>
        /// <returns>Модель строки таблицы</returns>
        private static CheckTemplateModel BuildCheckTemplateModel(HttpResponseEntity result)
        {
            string rowClass;
            string badgeClass;
            string badgeText;

            if (result.IsExecutionFailed)
            {
                rowClass = "failed-row";
                badgeClass = "badge failed";
                badgeText = "FAILED";
            }
            else if (result.IsSqlVulnerable)
            {
                rowClass = "vulnerable-row";
                badgeClass = "badge vulnerable";
                badgeText = "VULNERABLE";
            }
            else
            {
                rowClass = "safe-row";
                badgeClass = "badge safe";
                badgeText = "SAFE";
            }

            return new CheckTemplateModel
            {
                RowClass = rowClass,
                BadgeClass = badgeClass,
                BadgeText = badgeText,
                RequestType = HtmlEncode(result.RequestType),
                Endpoint = HtmlEncode(result.Endpoint),
                SqlInjectionType = HtmlEncode(result.SqlInjectionType.ToString()),
                StatusCode = HtmlEncode(result.IsExecutionFailed ? "N/A" : result.StatusCode.ToString()),
                Payload = HtmlEncode(result.Payload)
            };
        }

        /// <summary>
        /// Преобразование результата с ошибкой выполнения в модель для отдельного блока отчёта.
        /// </summary>
        /// <param name="result">Результат проверки, завершившейся ошибкой</param>
        /// <param name="index">Порядковый номер результата в блоке ошибок</param>
        /// <returns>Модель ошибочной проверки для шаблона</returns>
        private static FailedCheckTemplateModel BuildFailedCheckTemplateModel(HttpResponseEntity result, int index)
        {
            var details = new List<DetailsItemTemplateModel>
            {
                CreateDetailsItem("Полный адрес", result.UrlWithEndpoint),
                CreateDetailsItem("Payload", result.Payload),
                CreateDetailsItem("Тип запроса", result.RequestType),
                CreateDetailsItem("Тип SQL-инъекции", result.SqlInjectionType.ToString()),
                CreateDetailsItem("Ошибка выполнения", result.SqlInjectionSign)
            };

            if (result.RequestType == "POST" && !string.IsNullOrWhiteSpace(result.JsonBodyParams))
                details.Add(CreateDetailsItem("Тело запроса", result.JsonBodyParams));

            return new FailedCheckTemplateModel
            {
                Index = index,
                SqlInjectionType = HtmlEncode(result.SqlInjectionType.ToString()),
                RequestType = HtmlEncode(result.RequestType),
                Endpoint = HtmlEncode(result.Endpoint),
                Details = details
            };
        }

        /// <summary>
        /// Создание элемента детализации для раскрывающегося блока найденной уязвимости.
        /// </summary>
        /// <param name="title">Название поля</param>
        /// <param name="value">Значение поля</param>
        /// <returns>Модель элемента детализации</returns>
        private static DetailsItemTemplateModel CreateDetailsItem(string title, string value)
        {
            return new DetailsItemTemplateModel
            {
                Title = HtmlEncode(title),
                Value = HtmlEncode(value)
            };
        }

        /// <summary>
        /// HTML-экранирование строки перед вставкой в шаблон.
        /// </summary>
        /// <param name="value">Исходное значение</param>
        /// <returns>Безопасная HTML-строка</returns>
        private static string HtmlEncode(string? value)
        {
            return WebUtility.HtmlEncode(value ?? string.Empty);
        }

        /// <summary>
        /// Расчёт процента срабатываний среди всех выполненных проверок.
        /// </summary>
        /// <param name="totalChecks">Общее количество проверок</param>
        /// <param name="vulnerableChecks">Количество найденных срабатываний</param>
        /// <returns>Процент найденных срабатываний</returns>
        private static double GetVulnerablePercent(int totalChecks, int vulnerableChecks)
        {
            if (totalChecks == 0)
                return 0;

            return (double)vulnerableChecks / totalChecks * 100;
        }

        /// <summary>
        /// Корневая модель данных для HTML-шаблона отчёта.
        /// </summary>
        private sealed class ReportTemplateModel
        {
            public string GeneratedAt { get; set; } = string.Empty;
            public string PortalTypeDescription { get; set; } = string.Empty;
            public string BaseUrl { get; set; } = string.Empty;
            public int TotalChecks { get; set; }
            public int VulnerableChecks { get; set; }
            public int FailedChecks { get; set; }
            public int SafeChecks { get; set; }
            public string VulnerablePercent { get; set; } = string.Empty;
            public List<DistributionItemTemplateModel> Distribution { get; set; } = new();
            public List<VulnerabilityTemplateModel> Vulnerabilities { get; set; } = new();
            public List<FailedCheckTemplateModel> FailedChecksDetails { get; set; } = new();
            public List<CheckTemplateModel> Checks { get; set; } = new();
        }

        /// <summary>
        /// Модель элемента сводки по типу SQL-инъекции.
        /// </summary>
        private sealed class DistributionItemTemplateModel
        {
            public string SqlInjectionType { get; set; } = string.Empty;
            public int Count { get; set; }
        }

        /// <summary>
        /// Модель одного найденного срабатывания для блока детализации.
        /// </summary>
        private sealed class VulnerabilityTemplateModel
        {
            public int Index { get; set; }
            public string SqlInjectionType { get; set; } = string.Empty;
            public string RequestType { get; set; } = string.Empty;
            public string Endpoint { get; set; } = string.Empty;
            public List<DetailsItemTemplateModel> Details { get; set; } = new();
        }

        /// <summary>
        /// Модель одной проверки, которая не была выполнена из-за ошибки, для блока детализации отчёта.
        /// </summary>
        private sealed class FailedCheckTemplateModel
        {
            /// <summary>
            /// Порядковый номер записи в блоке ошибок.
            /// </summary>
            public int Index { get; set; }

            /// <summary>
            /// Тип SQL-инъекции, для которого выполнялась проверка.
            /// </summary>
            public string SqlInjectionType { get; set; } = string.Empty;

            /// <summary>
            /// Тип HTTP-запроса.
            /// </summary>
            public string RequestType { get; set; } = string.Empty;

            /// <summary>
            /// Эндпоинт, на котором произошла ошибка.
            /// </summary>
            public string Endpoint { get; set; } = string.Empty;

            /// <summary>
            /// Детализация ошибки для отображения в отчёте.
            /// </summary>
            public List<DetailsItemTemplateModel> Details { get; set; } = new();
        }

        /// <summary>
        /// Модель одного поля в карточке детализации найденной уязвимости.
        /// </summary>
        private sealed class DetailsItemTemplateModel
        {
            public string Title { get; set; } = string.Empty;
            public string Value { get; set; } = string.Empty;
        }

        /// <summary>
        /// Модель строки таблицы всех выполненных проверок.
        /// </summary>
        private sealed class CheckTemplateModel
        {
            public string RowClass { get; set; } = string.Empty;
            public string BadgeClass { get; set; } = string.Empty;
            public string BadgeText { get; set; } = string.Empty;
            public string RequestType { get; set; } = string.Empty;
            public string Endpoint { get; set; } = string.Empty;
            public string SqlInjectionType { get; set; } = string.Empty;
            public string StatusCode { get; set; } = string.Empty;
            public string Payload { get; set; } = string.Empty;
        }
    }
}
