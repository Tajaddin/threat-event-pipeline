create table if not exists rules (
    id         varchar(128) primary key,
    title      varchar(256) not null,
    severity   varchar(16)  not null,
    category   varchar(64),
    threshold  boolean      not null default false,
    tags       text         not null default '',
    yaml       text         not null,
    loaded_at  timestamptz  not null default now()
);

create table if not exists alerts (
    id                    uuid         primary key,
    rule_id               varchar(128) not null,
    rule_title            varchar(256) not null,
    severity              varchar(16)  not null,
    alert_key             varchar(512) not null,
    event_ids             jsonb        not null,
    event_count           int          not null,
    first_seen            timestamptz  not null,
    last_seen             timestamptz  not null,
    detected_at           timestamptz  not null,
    detection_latency_ms  bigint       not null,
    summary               text         not null
);
create index if not exists alerts_detected_idx on alerts (detected_at desc);
create index if not exists alerts_rule_idx on alerts (rule_id, detected_at desc);
create index if not exists alerts_severity_idx on alerts (severity, detected_at desc);
