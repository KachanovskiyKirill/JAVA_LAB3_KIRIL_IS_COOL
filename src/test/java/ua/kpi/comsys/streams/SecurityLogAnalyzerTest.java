package ua.kpi.comsys.streams;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(2) // жоден тест не повинен "зависнути" на нескінченному стрімі
class SecurityLogAnalyzerTest {

    private static final LocalDateTime BASE = LocalDateTime.of(2026, 1, 1, 12, 0);

    private SecurityLogAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new SecurityLogAnalyzer();
    }

    private static SecurityLog log(String ip, String severity, LocalDateTime time) {
        return new SecurityLog(ip, severity, "event from " + ip, time);
    }

    private static SecurityLog info(String ip) {
        return log(ip, "INFO", BASE);
    }

    // ------------------------------------------------------------------

    @Nested
    @DisplayName("findFirstCriticalEvent")
    class FindFirstCriticalEvent {

        @Test
        @DisplayName("нескінченний стрім: знаходить першу CRITICAL-подію і не читає зайвого")
        void findsCriticalInInfiniteStream() {
            AtomicInteger consumed = new AtomicInteger();
            Stream<SecurityLog> infinite = Stream.iterate(0, i -> i + 1)
                    .peek(i -> consumed.incrementAndGet())
                    .map(i -> i == 1000
                            ? log("10.0.0.1", "CRITICAL", BASE.plusSeconds(i))
                            : log("10.0.0.2", "WARNING", BASE.plusSeconds(i)));

            Optional<SecurityLog> result = analyzer.findFirstCriticalEvent(infinite);

            assertEquals(Optional.of("10.0.0.1"), result.map(SecurityLog::ipAddress));
            assertEquals(Optional.of(BASE.plusSeconds(1000)), result.map(SecurityLog::timestamp));
            assertEquals(1001, consumed.get(), "стрім має бути прочитаний лише до першого збігу");
        }

        @Test
        @DisplayName("Stream.generate: повертає саме першу з кількох критичних подій")
        void returnsVeryFirstCritical() {
            AtomicInteger counter = new AtomicInteger();
            Stream<SecurityLog> infinite = Stream.generate(() -> {
                int n = counter.getAndIncrement();
                return log("ip-" + n, n % 7 == 6 ? "CRITICAL" : "INFO", BASE);
            });

            String ip = analyzer.findFirstCriticalEvent(infinite)
                    .map(SecurityLog::ipAddress)
                    .orElse("none");

            assertEquals("ip-6", ip);
        }

        @Test
        @DisplayName("скінченний стрім без CRITICAL -> Optional.empty()")
        void emptyWhenNoCritical() {
            Stream<SecurityLog> finite = Stream.of(info("a"), log("b", "WARNING", BASE), log("c", "critical", BASE));

            assertTrue(analyzer.findFirstCriticalEvent(finite).isEmpty());
        }

        @Test
        @DisplayName("порожній стрім -> Optional.empty()")
        void emptyStream() {
            assertTrue(analyzer.findFirstCriticalEvent(Stream.empty()).isEmpty());
        }

        @Test
        @DisplayName("null-елементи та null-рівні пропускаються")
        void skipsNullElements() {
            Stream<SecurityLog> withNulls = Stream.of(null, log("x", null, BASE), log("y", "CRITICAL", BASE));

            assertEquals(Optional.of("y"), analyzer.findFirstCriticalEvent(withNulls).map(SecurityLog::ipAddress));
        }

        @Test
        @DisplayName("null stream -> IllegalArgumentException")
        void throwsOnNullStream() {
            assertThrows(IllegalArgumentException.class, () -> analyzer.findFirstCriticalEvent(null));
        }
    }

    // ------------------------------------------------------------------

    @Nested
    @DisplayName("getLogsBeforeDeadline")
    class GetLogsBeforeDeadline {

        private Stream<SecurityLog> everySecondFromBase() {
            return Stream.iterate(BASE, t -> t.plusSeconds(1))
                    .map(t -> log("10.0.0.1", "INFO", t));
        }

        @Test
        @DisplayName("нескінченний стрім: збирає події строго до дедлайну")
        void collectsUntilDeadline() {
            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(everySecondFromBase(), BASE.plusSeconds(10));

            assertEquals(10, result.size());
            assertEquals(BASE, result.getFirst().timestamp());
            assertEquals(BASE.plusSeconds(9), result.getLast().timestamp());
        }

        @Test
        @DisplayName("подія рівно в момент дедлайну вже не включається")
        void deadlineIsExclusive() {
            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(everySecondFromBase(), BASE.plusSeconds(1));

            assertEquals(List.of(BASE), result.stream().map(SecurityLog::timestamp).toList());
        }

        @Test
        @DisplayName("дедлайн раніше за першу подію -> порожній список")
        void deadlineBeforeFirstEvent() {
            assertTrue(analyzer.getLogsBeforeDeadline(everySecondFromBase(), BASE.minusDays(1)).isEmpty());
        }

        @Test
        @DisplayName("збір зупиняється на першій пізній події, навіть якщо далі є ранні (takeWhile, а не filter)")
        void stopsAtFirstLateEvent() {
            Stream<SecurityLog> logs = Stream.of(
                    log("a", "INFO", BASE),
                    log("b", "INFO", BASE.plusHours(5)),
                    log("c", "INFO", BASE.plusSeconds(1)));

            List<SecurityLog> result = analyzer.getLogsBeforeDeadline(logs, BASE.plusHours(1));

            assertEquals(List.of("a"), result.stream().map(SecurityLog::ipAddress).toList());
        }

        @Test
        @DisplayName("скінченний стрім, увесь до дедлайну -> повертаються всі події")
        void finiteStreamFullyBeforeDeadline() {
            Stream<SecurityLog> logs = Stream.of(info("a"), info("b"));

            assertEquals(2, analyzer.getLogsBeforeDeadline(logs, BASE.plusDays(1)).size());
        }

        @Test
        @DisplayName("null-елемент або подія без часу завершують збір")
        void nullElementOrTimestampStops() {
            List<SecurityLog> withNull = Arrays.asList(info("a"), null, info("b"));
            List<SecurityLog> withNullTime = List.of(info("a"), log("x", "INFO", null), info("b"));

            assertEquals(1, analyzer.getLogsBeforeDeadline(withNull.stream(), BASE.plusDays(1)).size());
            assertEquals(1, analyzer.getLogsBeforeDeadline(withNullTime.stream(), BASE.plusDays(1)).size());
        }

        @Test
        @DisplayName("null-аргументи -> IllegalArgumentException")
        void throwsOnNullArguments() {
            assertThrows(IllegalArgumentException.class, () -> analyzer.getLogsBeforeDeadline(null, BASE));
            assertThrows(IllegalArgumentException.class, () -> analyzer.getLogsBeforeDeadline(Stream.empty(), null));
        }
    }

    // ------------------------------------------------------------------

    @Nested
    @DisplayName("detectIpBursts")
    class DetectIpBursts {

        /** Кожна IP-адреса 10.0.0.N повторюється 5 разів поспіль, і так нескінченно. */
        private Stream<SecurityLog> infiniteRunsOfFive(AtomicInteger consumed) {
            return Stream.iterate(0, i -> i + 1)
                    .peek(i -> consumed.incrementAndGet())
                    .map(i -> info("10.0.0." + (i / 5)));
        }

        @Test
        @DisplayName("нескінченний стрім: повертає рівно maxIpsToReport адрес і зупиняється")
        void stopsAfterMaxIpsOnInfiniteStream() {
            AtomicInteger consumed = new AtomicInteger();

            List<String> result = analyzer.detectIpBursts(infiniteRunsOfFive(consumed), 3, 4);

            assertEquals(List.of("10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"), result);
            // 4-й сплеск фіксується на 18-й події (3*5 + 3); далі стрім не читається
            assertTrue(consumed.get() < 25, "Gatherer має зупинити читання, прочитано: " + consumed.get());
        }

        @Test
        @DisplayName("Stream.generate з одним IP: перший сплеск зупиняє обробку при maxIpsToReport = 1")
        void singleIpInfiniteStream() {
            Stream<SecurityLog> infinite = Stream.generate(() -> info("6.6.6.6"));

            assertEquals(List.of("6.6.6.6"), analyzer.detectIpBursts(infinite, 100, 1));
        }

        @Test
        @DisplayName("серія, довша за поріг, повідомляється лише один раз")
        void longRunReportedOnce() {
            Stream<SecurityLog> logs = Stream.of(info("a"), info("a"), info("a"), info("a"), info("a"), info("b"));

            assertEquals(List.of("a"), analyzer.detectIpBursts(logs, 2, 10));
        }

        @Test
        @DisplayName("серія, коротша за поріг, не є сплеском")
        void shortRunsIgnored() {
            Stream<SecurityLog> logs = Stream.of(info("a"), info("a"), info("b"), info("a"), info("a"));

            assertTrue(analyzer.detectIpBursts(logs, 3, 10).isEmpty());
        }

        @Test
        @DisplayName("події від інших IP переривають серію")
        void otherIpBreaksRun() {
            Stream<SecurityLog> alternating = Stream.of(info("a"), info("b"), info("a"), info("b"), info("a"));

            assertTrue(analyzer.detectIpBursts(alternating, 2, 10).isEmpty());
        }

        @Test
        @DisplayName("та сама IP у двох окремих серіях повідомляється двічі")
        void separateRunsOfSameIp() {
            Stream<SecurityLog> logs = Stream.of(
                    info("a"), info("a"), info("b"), info("a"), info("a"));

            assertEquals(List.of("a", "a"), analyzer.detectIpBursts(logs, 2, 10));
        }

        @Test
        @DisplayName("null-елемент або null IP переривають серію")
        void nullBreaksRun() {
            List<SecurityLog> logs = Arrays.asList(info("a"), null, info("a"), info(null), info("a"));

            assertTrue(analyzer.detectIpBursts(logs.stream(), 2, 10).isEmpty());
        }

        @ParameterizedTest(name = "threshold={0}, max={1} -> {2} сплесків")
        @CsvSource({
                "1, 3, 3",
                "5, 2, 2",
                "6, 2, 0"
        })
        @DisplayName("поріг і ліміт на скінченному стрімі")
        void thresholdAndLimit(int threshold, int max, int expectedCount) {
            AtomicInteger ignored = new AtomicInteger();
            Stream<SecurityLog> finite = infiniteRunsOfFive(ignored).limit(25); // 5 серій по 5

            assertEquals(expectedCount, analyzer.detectIpBursts(finite, threshold, max).size());
        }

        @Test
        @DisplayName("некоректні аргументи -> IllegalArgumentException")
        void throwsOnInvalidArguments() {
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(null, 2, 2));
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(Stream.empty(), 0, 2));
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(Stream.empty(), -1, 2));
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(Stream.empty(), 2, 0));
            assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(Stream.empty(), 2, -3));
        }
    }
}
