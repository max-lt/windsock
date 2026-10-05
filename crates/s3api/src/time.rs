//! Date formats of the S3 API: ISO 8601 in XML, IMF-fixdate in HTTP headers.

const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Civil date of a day count since 1970-01-01 (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Day count since 1970-01-01 of a civil date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Days since 1970-01-01, and seconds into that day.
fn split(nanos: u64) -> (i64, u64) {
    let secs = nanos / 1_000_000_000;
    ((secs / 86_400) as i64, secs % 86_400)
}

/// `2026-10-05T12:00:00.000Z`
pub fn iso8601(unix_nanos: u64) -> String {
    let (days, secs) = split(unix_nanos);
    let (y, m, d) = civil(days);
    let millis = (unix_nanos / 1_000_000) % 1000;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// `Mon, 05 Oct 2026 12:00:00 GMT`
pub fn http_date(unix_nanos: u64) -> String {
    let (days, secs) = split(unix_nanos);
    let (y, m, d) = civil(days);
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[m as usize - 1],
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// `20261005T120000Z`, the `x-amz-date` form.
pub fn amz_date(unix_secs: u64) -> String {
    let (y, m, d) = civil((unix_secs / 86_400) as i64);
    let secs = unix_secs % 86_400;
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Unix seconds of an IMF-fixdate, the only date form HTTP senders must use.
pub fn parse_http_date(text: &str) -> Option<u64> {
    let mut parts = text.split_whitespace();
    let _weekday = parts.next()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let month = MONTHS.iter().position(|m| *m == month_name)? as u32 + 1;
    let year: i64 = parts.next()?.parse().ok()?;
    let mut clock = parts.next()?.split(':').map(|n| n.parse::<u64>().ok());
    let (h, min, s) = (clock.next()??, clock.next()??, clock.next()??);

    if parts.next()? != "GMT" || h > 23 || min > 59 || s > 60 || !(1..=31).contains(&day) {
        return None;
    }

    let days = u64::try_from(days_from_civil(year, month, day)).ok()?;
    Some(days * 86_400 + h * 3600 + min * 60 + s)
}

/// Unix seconds of an `x-amz-date` value: `20261005T120000Z`.
pub fn parse_amz_date(text: &str) -> Option<u64> {
    if text.len() != 16 || !text.is_ascii() || &text[8..9] != "T" || &text[15..] != "Z" {
        return None;
    }

    let num = |range: std::ops::Range<usize>| text[range].parse::<u64>().ok();
    let days = days_from_civil(num(0..4)? as i64, num(4..6)? as u32, num(6..8)? as u32);
    let days = u64::try_from(days).ok()?;
    Some(days * 86_400 + num(9..11)? * 3600 + num(11..13)? * 60 + num(13..15)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-05T12:34:56.789Z, a Monday.
    const SAMPLE: u64 = 1_791_203_696_789_000_000;

    #[test]
    fn test_iso8601() {
        assert_eq!(iso8601(SAMPLE), "2026-10-05T12:34:56.789Z");
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn test_http_date_roundtrip() {
        let text = http_date(SAMPLE);

        assert_eq!(text, "Mon, 05 Oct 2026 12:34:56 GMT");
        assert_eq!(parse_http_date(&text), Some(SAMPLE / 1_000_000_000));
    }

    #[test]
    fn test_leap_day() {
        let secs = parse_http_date("Thu, 29 Feb 2024 00:00:00 GMT").unwrap();

        assert_eq!(
            http_date(secs * 1_000_000_000),
            "Thu, 29 Feb 2024 00:00:00 GMT"
        );
    }

    #[test]
    fn test_parse_http_date_rejects_other_forms() {
        assert_eq!(parse_http_date("Monday, 05-Oct-26 12:34:56 GMT"), None);
        assert_eq!(parse_http_date("Mon, 05 Oct 2026 12:34:56 UTC"), None);
        assert_eq!(parse_http_date(""), None);
    }

    #[test]
    fn test_parse_amz_date() {
        assert_eq!(
            parse_amz_date("20261005T123456Z"),
            Some(SAMPLE / 1_000_000_000)
        );
        assert_eq!(parse_amz_date("2026-10-05T12:34:56Z"), None);
        assert_eq!(amz_date(SAMPLE / 1_000_000_000), "20261005T123456Z");
    }
}
