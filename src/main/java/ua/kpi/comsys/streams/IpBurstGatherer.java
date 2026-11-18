package ua.kpi.comsys.streams;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Gatherer;

/**
 * Кастомна проміжна операція (stateful, послідовна) для детекції атак типу "Burst".
 *
 * <p>Gatherer рахує довжину неперервної серії подій від однієї IP-адреси. Щойно серія
 * досягає {@code burstThreshold} подій, IP-адреса передається далі по конвеєру (рівно
 * один раз за серію). Після того як знайдено {@code maxIpsToReport} сплесків, Gatherer
 * повертає {@code false} з інтегратора — це коротке замикання, яке зупиняє споживання
 * навіть нескінченного джерела.
 *
 * <p>Якщо та сама IP-адреса пізніше створить нову окрему серію (після подій від інших IP),
 * вона буде повідомлена ще раз — це новий інцидент.
 * Подія з {@code null} або без IP-адреси перериває поточну серію.
 */
public final class IpBurstGatherer implements Gatherer<SecurityLog, IpBurstGatherer.State, String> {

    private final int burstThreshold;
    private final int maxIpsToReport;

    /**
     * @param burstThreshold мінімальна довжина серії (&gt; 0)
     * @param maxIpsToReport максимальна кількість сплесків у звіті (&gt; 0)
     * @throws IllegalArgumentException якщо будь-який параметр &lt;= 0
     */
    public IpBurstGatherer(int burstThreshold, int maxIpsToReport) {
        if (burstThreshold <= 0) {
            throw new IllegalArgumentException("burstThreshold must be greater than 0");
        }
        if (maxIpsToReport <= 0) {
            throw new IllegalArgumentException("maxIpsToReport must be greater than 0");
        }
        this.burstThreshold = burstThreshold;
        this.maxIpsToReport = maxIpsToReport;
    }

    /**
     * Змінний стан Gatherer-а. Створюється окремо для кожного виконання стріма.
     */
    public static final class State {
        private String currentIp;
        private int runLength;
        private int reported;

        private State() {
        }

        private void resetRun() {
            currentIp = null;
            runLength = 0;
        }
    }

    @Override
    public Supplier<State> initializer() {
        return State::new;
    }

    @Override
    public Integrator<State, SecurityLog, String> integrator() {
        // Integrator.of (не ofGreedy), бо ми самі можемо зупинити обробку.
        return Integrator.of((state, log, downstream) -> {
            String ip = (log == null) ? null : log.ipAddress();
            if (ip == null) {
                state.resetRun();
                return !downstream.isRejecting();
            }

            if (Objects.equals(ip, state.currentIp)) {
                state.runLength++;
            } else {
                state.currentIp = ip;
                state.runLength = 1;
            }

            if (state.runLength == burstThreshold) {
                state.reported++;
                boolean downstreamWantsMore = downstream.push(ip);
                return downstreamWantsMore && state.reported < maxIpsToReport;
            }
            return !downstream.isRejecting();
        });
    }
}
