namespace WebVulnerabilitiesScanner.Entities
{
    /// <summary>
    /// Пара нагрузок для проверки boolean-based SQL-инъекции.
    /// </summary>
    public class BooleanBasedPayloadPairEntity
    {
        public BooleanBasedPayloadPairEntity(RequestSqlInjectionPayloadEntity truePayloadInfo, RequestSqlInjectionPayloadEntity falsePayloadInfo)
        {
            TruePayloadInfo = truePayloadInfo;
            FalsePayloadInfo = falsePayloadInfo;
        }

        /// <summary>
        /// Нагрузка, которая должна вернуть "истинный" ответ.
        /// </summary>
        public RequestSqlInjectionPayloadEntity TruePayloadInfo { get; set; }

        /// <summary>
        /// Нагрузка, которая должна вернуть "ложный" ответ.
        /// </summary>
        public RequestSqlInjectionPayloadEntity FalsePayloadInfo { get; set; }
    }
}
