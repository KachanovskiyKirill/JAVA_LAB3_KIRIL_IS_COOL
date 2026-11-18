package ua.kpi.comsys.streams;

import java.time.LocalDateTime;

/**
 * Запис журналу безпеки.
 *
 * @param ipAddress        IP-адреса джерела події
 * @param severityLevel    рівень серйозності (наприклад, INFO, WARNING, CRITICAL)
 * @param eventDescription опис події
 * @param timestamp        час події
 */
public record SecurityLog(String ipAddress, String severityLevel, String eventDescription,
                          LocalDateTime timestamp) {
}
