use chrono::Utc;
use lightning::util::logger::{Logger, Record};

pub(crate) struct ConsoleLogger {
    pub name: String,
}

impl Logger for ConsoleLogger {
    fn log(&self, record: &Record) {
        let raw_log = record.args.to_string();
        let log = format!(
            "From {}: {} {:<5} [{}:{}] {}\n",
            // Note that a "real" lightning node almost certainly does *not* want subsecond
            // precision for message-receipt information as it makes log entries a target for
            // deanonymization attacks. For testing, however, its quite useful.
            self.name,
            Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level.to_string(),
            record.module_path,
            record.line,
            raw_log
        );
        println!("{}", log);
    }
}
