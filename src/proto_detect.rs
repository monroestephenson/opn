/// Heuristically detect the application-layer protocol for a connection.
///
/// Checks process name first (fast, accurate for well-known daemons), then
/// falls back to port-number mapping.  Returns `None` when nothing matches.
pub fn detect(local_port: u16, process_name: &str) -> Option<&'static str> {
    // Process-name hints take priority – they're more reliable than port numbers.
    let name = process_name.to_ascii_lowercase();
    let name = name.trim_end_matches(':'); // strip trailing colon some platforms add
    if name == "sshd" || name == "ssh" {
        return Some("SSH");
    }
    if name.starts_with("postgres") || name == "pg_ctl" {
        return Some("PostgreSQL");
    }
    if name == "redis-server" || name == "redis" {
        return Some("Redis");
    }
    if name == "mysqld" || name == "mysql" || name == "mariadbd" {
        return Some("MySQL");
    }
    if name == "mongod" || name == "mongos" {
        return Some("MongoDB");
    }
    if name == "nginx" {
        return Some("HTTP");
    }
    if name == "httpd" || name == "apache2" || name == "apache" {
        return Some("HTTP");
    }
    if name == "named" || name == "unbound" || name == "dnsmasq" || name == "coredns" {
        return Some("DNS");
    }
    if name == "memcached" {
        return Some("Memcached");
    }
    if name == "etcd" {
        return Some("etcd");
    }
    if name == "kafka" || name == "kafka-server-start" {
        return Some("Kafka");
    }
    if name == "zookeeper" {
        return Some("ZooKeeper");
    }

    // Port-based fallback.
    match local_port {
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("Telnet"),
        25 | 587 | 465 => Some("SMTP"),
        53 => Some("DNS"),
        80 | 8080 | 8000 => Some("HTTP"),
        110 => Some("POP3"),
        143 => Some("IMAP"),
        389 => Some("LDAP"),
        443 | 8443 => Some("HTTPS"),
        636 => Some("LDAPS"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        1521 => Some("Oracle DB"),
        2181 | 2888 | 3888 => Some("ZooKeeper"),
        2379 | 2380 => Some("etcd"),
        3000 => Some("HTTP"),
        3306 => Some("MySQL"),
        5432 => Some("PostgreSQL"),
        5672 => Some("AMQP"),
        6379 => Some("Redis"),
        6443 => Some("Kubernetes API"),
        8086 => Some("InfluxDB"),
        9042 => Some("Cassandra"),
        9092 => Some("Kafka"),
        9200 | 9300 => Some("Elasticsearch"),
        11211 => Some("Memcached"),
        15672 => Some("RabbitMQ"),
        27017 | 27018 => Some("MongoDB"),
        50051 => Some("gRPC"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_name_beats_port() {
        // sshd on port 80 should still be SSH
        assert_eq!(detect(80, "sshd"), Some("SSH"));
    }

    #[test]
    fn port_fallback_http() {
        assert_eq!(detect(80, "unknown"), Some("HTTP"));
        assert_eq!(detect(8080, "unknown"), Some("HTTP"));
        assert_eq!(detect(443, "unknown"), Some("HTTPS"));
    }

    #[test]
    fn port_fallback_databases() {
        assert_eq!(detect(5432, "unknown"), Some("PostgreSQL"));
        assert_eq!(detect(3306, "unknown"), Some("MySQL"));
        assert_eq!(detect(6379, "unknown"), Some("Redis"));
        assert_eq!(detect(27017, "unknown"), Some("MongoDB"));
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(detect(12345, "myapp"), None);
    }

    #[test]
    fn process_name_postgres() {
        assert_eq!(detect(9999, "postgres"), Some("PostgreSQL"));
        assert_eq!(detect(9999, "postgresql"), Some("PostgreSQL"));
    }

    #[test]
    fn process_name_nginx() {
        assert_eq!(detect(9999, "nginx"), Some("HTTP"));
    }
}
