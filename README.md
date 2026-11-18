# Лабораторна робота №3 — Нескінченні стріми, Optional та Stream Gatherers

**Дисципліна:** Технології розробки на платформі Java, КПІ ім. Ігоря Сікорського
**Тема:** ледачі (lazy) операції Stream API над нескінченними послідовностями, безпечна робота з `Optional`, кастомні проміжні операції через `java.util.stream.Gatherer`

| | |
|---|---|
| **Студент** | Качановський Кирило Станіславович |
| **Група** | ІО-45 |
| **Номер у списку** | 5 |
| **Залікова книжка** | 4505 |
| **Варіант** | **2** — обробка безпекових подій |

## Зміст

- [Розрахунок варіанта](#розрахунок-варіанта)
- [Опис проєкту](#опис-проєкту)
- [Модель даних](#модель-даних)
- [Сервіс SecurityLogAnalyzer](#сервіс-securityloganalyzer)
- [Кастомний Gatherer](#кастомний-gatherer)
- [Валідація аргументів](#валідація-аргументів)
- [Тести](#тести)
- [Запуск тестів](#запуск-тестів)
- [Структура проєкту](#структура-проєкту)

## Розрахунок варіанта

```
V = N mod 3
N = 4505
4505 = 3 · 1501 + 2   →   V = 2
```

## Опис проєкту

Сервіс аналітики приймає потенційно **нескінченний** потік журналів безпеки (`Stream<SecurityLog>`), безпечно його фільтрує та аналізує. Усі методи використовують лише ледачі операції та операції короткого замикання (`findFirst`, `takeWhile`, зупинка у власному `Gatherer`), тому не блокуються на нескінченних джерелах (`Stream.generate`, `Stream.iterate`), якщо шукана умова колись настає.

Усі типи знаходяться в пакеті `ua.kpi.comsys.streams`.

## Модель даних

```java
public record SecurityLog(String ipAddress, String severityLevel,
                          String eventDescription, LocalDateTime timestamp) {}
```

## Сервіс SecurityLogAnalyzer

| Метод | Що робить | Реалізація |
|---|---|---|
| `Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream)` | знаходить першу подію з `severityLevel == "CRITICAL"` | `filter` + `findFirst` |
| `List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline)` | збирає події, доки не настане дедлайн | `takeWhile(timestamp < deadline)` |
| `List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport)` | знаходить IP-адреси, від яких надійшло `≥ burstThreshold` подій поспіль | власний `Gatherer` |

Деталі поведінки:

- `findFirstCriticalEvent` повертає `Optional.empty()`, якщо у скінченному стрімі немає критичних подій. Елементи `null` пропускаються.
- `getLogsBeforeDeadline`: подія рівно в момент дедлайну вже **не** включається. Збір завершується на першій події з часом `≥ deadline`, а також на елементі `null` або події без часу. Це саме `takeWhile`, а не `filter`: подія, що трапилась пізніше, але стоїть у стрімі раніше за «ранні», обриває збір.
- `detectIpBursts` обробляє події послідовно; рахується довжина **неперервної** серії від однієї IP.

## Кастомний Gatherer

`IpBurstGatherer implements Gatherer<SecurityLog, IpBurstGatherer.State, String>` — послідовна проміжна операція зі станом.

**Стан** (окремий для кожного виконання стріма): поточна IP, довжина поточної серії, кількість уже знайдених сплесків.

**Алгоритм інтегратора** для кожної події:

1. Якщо IP збігається з поточною — довжина серії збільшується, інакше серія починається заново з 1. Подія `null` або з `null`-IP перериває серію.
2. Коли довжина серії **дорівнює** `burstThreshold`, IP передається далі по конвеєру. Тому серія довша за поріг повідомляється лише один раз.
3. Коли знайдено `maxIpsToReport` сплесків, інтегратор повертає `false` — це коротке замикання, яке зупиняє споживання навіть нескінченного джерела.

Якщо та сама IP пізніше створить нову окрему серію (після подій від інших IP), вона буде повідомлена ще раз як новий інцидент.

**Приклад** (`burstThreshold = 2`):

| Потік подій (IP) | Результат |
|---|---|
| `a a a a a b` | `[a]` |
| `a a b a a` | `[a, a]` |
| `a b a b a` | `[]` |

## Валідація аргументів

Усі порушення призводять до `IllegalArgumentException`:

- `stream == null` (у всіх трьох методах);
- `deadline == null` у `getLogsBeforeDeadline`;
- `burstThreshold <= 0` або `maxIpsToReport <= 0` у `detectIpBursts`.

Перевірки зроблено функціонально через `Optional.ofNullable(...).orElseThrow(...)`, без `Optional.get()`.

## Тести

Тести використовують **нескінченні джерела** (`Stream.iterate`, `Stream.generate`), а на класи тестів додано `@Timeout(2)`, щоб підтвердити відсутність зависань. Лічильники в `peek` показують, що стрім читається лише до потрібного елемента.

- **`SecurityLogAnalyzerTest`** (групи `@Nested`):
  - `findFirstCriticalEvent` — нескінченний стрім, перша з кількох критичних подій, відсутність збігів, порожній стрім, `null`-елементи, `null` стрім;
  - `getLogsBeforeDeadline` — нескінченний стрім, дедлайн як виключна межа, дедлайн раніше першої події, зупинка на першій пізній події, скінченний стрім, `null`-елементи, `null`-аргументи;
  - `detectIpBursts` — зупинка після `maxIpsToReport` на нескінченному стрімі, довга серія (одне повідомлення), коротка серія, переривання серії іншою IP, повторні серії, `null`, параметризований тест порогу й ліміту, некоректні аргументи.
- **`IpBurstGathererTest`** — використання напряму в `Stream.gather(...)`, обмеження `limit` після `gather`, окремий стан для кожного виконання стріма, валідація конструктора.

## Запуск тестів

Stream Gatherers (`java.util.stream.Gatherer`) стали стабільним API в **Java 24**, тому проєкт збирається на **Java 25 (LTS)** через Gradle toolchain. Якщо потрібного JDK немає, Gradle завантажить його автоматично (плагін `foojay-resolver-convention`). Gradle встановлювати не треба — використовується Gradle Wrapper.

**Linux / macOS**

```bash
./gradlew test       # запустити тести
./gradlew build      # компіляція + тести
```

**Windows**

```bat
gradlew.bat test
```

Після запуску доступні звіти:

- результати тестів: `build/reports/tests/test/index.html`
- покриття коду (JaCoCo): `build/reports/jacoco/test/html/index.html`

Залежності керуються через Version Catalog `gradle/libs.versions.toml` (JUnit 5 підключається через BOM).

## Структура проєкту

```
.
├── build.gradle.kts
├── settings.gradle.kts
├── gradle/
│   ├── libs.versions.toml        # Version Catalog
│   └── wrapper/
├── src/
│   ├── main/java/ua/kpi/comsys/streams/
│   │   ├── SecurityLog.java
│   │   ├── SecurityLogAnalyzer.java
│   │   └── IpBurstGatherer.java
│   └── test/java/ua/kpi/comsys/streams/
│       ├── SecurityLogAnalyzerTest.java
│       └── IpBurstGathererTest.java
└── README.md
```

## Технології

Java 25 · Gradle (Kotlin DSL) з Version Catalog · JUnit 5 · JaCoCo · Stream API / Gatherers
