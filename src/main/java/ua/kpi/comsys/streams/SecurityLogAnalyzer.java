package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Аналізатор (потенційно нескінченного) потоку журналів безпеки.
 *
 * <p>Усі методи використовують лише ледачі операції та операції короткого замикання
 * ({@code findFirst}, {@code takeWhile}, власний Gatherer зі зупинкою), тож не
 * блокуються на нескінченних стрімах, якщо шукана умова колись настає.
 */
public class SecurityLogAnalyzer {

    static final String CRITICAL = "CRITICAL";

    /**
     * Знаходить першу подію з рівнем {@code CRITICAL}.
     *
     * <p>На скінченному стрімі без критичних подій повертає {@link Optional#empty()}.
     * На нескінченному стрімі зупиняється на першій знайденій події.
     *
     * @throws IllegalArgumentException якщо {@code stream == null}
     */
    public Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream) {
        return requireArgument(stream, "stream cannot be null")
                .filter(Objects::nonNull)
                .filter(log -> CRITICAL.equals(log.severityLevel()))
                .findFirst();
    }

    /**
     * Збирає події, доки не настане дедлайн: бере елементи з початку стріма, поки
     * {@code timestamp} строго раніше за {@code deadline}. Перша подія з часом
     * {@code >= deadline} (або без часу) завершує збір.
     *
     * @throws IllegalArgumentException якщо {@code stream == null} або {@code deadline == null}
     */
    public List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline) {
        Stream<SecurityLog> source = requireArgument(stream, "stream cannot be null");
        LocalDateTime limit = requireArgument(deadline, "deadline cannot be null");

        return source
                .takeWhile(log -> Optional.ofNullable(log)
                        .map(SecurityLog::timestamp)
                        .map(time -> time.isBefore(limit))
                        .orElse(false))
                .toList();
    }

    /**
     * Виявляє IP-адреси, від яких надійшло {@code >= burstThreshold} подій поспіль
     * (без подій від інших IP між ними). Обробка зупиняється, щойно знайдено
     * {@code maxIpsToReport} сплесків.
     *
     * @throws IllegalArgumentException якщо {@code stream == null}, {@code burstThreshold <= 0}
     *                                  або {@code maxIpsToReport <= 0}
     */
    public List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport) {
        Stream<SecurityLog> source = requireArgument(stream, "stream cannot be null");
        IpBurstGatherer gatherer = new IpBurstGatherer(burstThreshold, maxIpsToReport);

        return source
                .gather(gatherer)
                .toList();
    }

    private static <T> T requireArgument(T value, String message) {
        return Optional.ofNullable(value)
                .orElseThrow(() -> new IllegalArgumentException(message));
    }
}
