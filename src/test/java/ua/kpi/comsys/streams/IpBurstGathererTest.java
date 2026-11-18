package ua.kpi.comsys.streams;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Timeout(2)
class IpBurstGathererTest {

    private static SecurityLog log(String ip) {
        return new SecurityLog(ip, "INFO", "test", LocalDateTime.of(2026, 1, 1, 0, 0));
    }

    @Test
    @DisplayName("Gatherer можна використовувати напряму в Stream.gather(...) на нескінченному стрімі")
    void worksAsIntermediateOperation() {
        // Патерн: a a b b b c c c c ... (IP номер n повторюється n+2 разів)
        Stream<SecurityLog> infinite = Stream.iterate(0, n -> n + 1)
                .flatMap(n -> Stream.generate(() -> log("ip" + n)).limit(n + 2L));

        List<String> result = infinite.gather(new IpBurstGatherer(3, 3)).toList();

        assertEquals(List.of("ip1", "ip2", "ip3"), result);
    }

    @Test
    @DisplayName("Gatherer поважає обмеження downstream (limit після gather)")
    void respectsDownstreamLimit() {
        AtomicInteger n = new AtomicInteger();
        Stream<SecurityLog> infinite = Stream.generate(() -> log("ip" + n.getAndIncrement()));

        List<String> result = infinite
                .gather(new IpBurstGatherer(1, Integer.MAX_VALUE))
                .limit(2)
                .toList();

        assertEquals(List.of("ip0", "ip1"), result);
    }

    @Test
    @DisplayName("кожне виконання стріма отримує власний стан")
    void stateIsNotSharedBetweenRuns() {
        IpBurstGatherer gatherer = new IpBurstGatherer(2, 1);

        List<String> first = Stream.of(log("a"), log("a")).gather(gatherer).toList();
        List<String> second = Stream.of(log("b"), log("b")).gather(gatherer).toList();

        assertEquals(List.of("a"), first);
        assertEquals(List.of("b"), second);
    }

    @Test
    @DisplayName("конструктор перевіряє параметри")
    void validatesParameters() {
        assertThrows(IllegalArgumentException.class, () -> new IpBurstGatherer(0, 1));
        assertThrows(IllegalArgumentException.class, () -> new IpBurstGatherer(1, 0));
    }
}
