using System.ComponentModel;

namespace WebVulnerabilitiesScanner.Entities
{
    /// <summary>
    /// Сущность нагрузки для SQL-инъекции
    /// </summary>
    public class RequestSqlInjectionPayloadEntity
    {
        public RequestSqlInjectionPayloadEntity(string payload, SqlInjectionType sqlInjectionType)
        {
            Payload = payload;
            SqlInjectionType = sqlInjectionType;
        }

        /// <summary>
        /// Полезная нагрузка
        /// </summary>
        public string Payload { get; set; }

        /// <summary>
        /// Тип SQL-инъекции
        /// </summary>
        public SqlInjectionType SqlInjectionType { get; set; }
    }

    public enum SqlInjectionType 
    {
        [Description("Union-based SQL-инъекция")]
        UnionBased,

        [Description("Error-based SQL-инъекция")]
        ErrorBased,

        [Description("Time-based SQL-инъекция")]
        TimeBasedBlind,

        [Description("Boolean-based SQL-инъекция")]
        BooleanBased,

        [Description("Stacked Queries")]
        StackedQueries
    }
}
