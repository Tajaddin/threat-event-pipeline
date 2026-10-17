-- Synthetic context tables. ip_ranges plays the role of a GeoIP/ASN database; assets of a CMDB.
create table if not exists ip_ranges (
    cidr      cidr        primary key,
    country   varchar(2),
    asn       varchar(32),
    internal  boolean     not null default false,
    label     varchar(64)
);
create index if not exists ip_ranges_gist on ip_ranges using gist (cidr inet_ops);

create table if not exists assets (
    hostname     varchar(128) primary key,
    owner        varchar(64)  not null,
    criticality  varchar(16)  not null check (criticality in ('low', 'medium', 'high', 'critical')),
    role         varchar(64)
);

insert into ip_ranges (cidr, country, asn, internal, label) values
    ('10.0.0.0/8',        'US', 'AS0-internal',     true,  'corporate'),
    ('172.16.0.0/12',     'US', 'AS0-internal',     true,  'corporate'),
    ('192.168.0.0/16',    'US', 'AS0-internal',     true,  'corporate'),
    ('203.0.113.0/24',    'US', 'AS64500-docnet',   false, 'documentation range'),
    ('198.51.100.0/24',   'DE', 'AS64501-docnet',   false, 'documentation range'),
    ('192.0.2.0/24',      'BR', 'AS64502-docnet',   false, 'documentation range'),
    ('185.220.101.0/24',  'NL', 'AS64503-exitnode', false, 'synthetic hostile'),
    ('45.155.205.0/24',   'RU', 'AS64504-bullet',   false, 'synthetic hostile')
on conflict do nothing;

insert into assets (hostname, owner, criticality, role) values
    ('srv-dc-01',   'infrastructure', 'critical', 'domain controller'),
    ('srv-sql-01',  'data',           'critical', 'database'),
    ('srv-file-01', 'infrastructure', 'high',     'file server'),
    ('srv-web-01',  'web',            'high',     'web server'),
    ('srv-vpn-01',  'network',        'high',     'vpn gateway'),
    ('srv-jump-01', 'security',       'high',     'jump host'),
    ('fw-edge-01',  'network',        'critical', 'edge firewall'),
    ('lt-exec-01',  'executive',      'high',     'laptop'),
    ('lt-exec-02',  'executive',      'high',     'laptop'),
    ('ws-0101', 'finance', 'medium', 'workstation'), ('ws-0102', 'finance', 'medium', 'workstation'),
    ('ws-0103', 'finance', 'medium', 'workstation'), ('ws-0104', 'hr', 'medium', 'workstation'),
    ('ws-0105', 'hr', 'medium', 'workstation'), ('ws-0201', 'engineering', 'low', 'workstation'),
    ('ws-0202', 'engineering', 'low', 'workstation'), ('ws-0203', 'engineering', 'low', 'workstation')
on conflict do nothing;
