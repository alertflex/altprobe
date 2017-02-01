/**************************************************
Before execution of this script,
it is necessary to set the following parameters for UTF-8 encode of MySQL DB in file: /etc/mysql/my.cnf

[client]
default-character-set=utf8

[mysql]
default-character-set=utf8

[mysqld]
collation-server = utf8_unicode_ci
init-connect='SET NAMES utf8'
character-set-server = utf8

*****************************************************/

CREATE DATABASE alt_probe;
/* For remote access */
GRANT ALL ON alt_probe.* TO root@'localhost' IDENTIFIED BY 'XXX';


CREATE TABLE `suricata_events` (
  `event_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `probe_id` varchar(128) NOT NULL DEFAULT '',
  `time_of_event` datetime DEFAULT NULL,
  `time_stamp` varchar(32) NOT NULL DEFAULT '',
  `flow_id` int(10) unsigned NOT NULL DEFAULT '0',
  `stream` int(10) unsigned NOT NULL DEFAULT '0',
  `in_iface` varchar(8) NOT NULL DEFAULT '',
  `event_type` varchar(128) NOT NULL DEFAULT '',
  `srcip` varchar(32) NOT NULL DEFAULT '',
  `dstip` varchar(32) NOT NULL DEFAULT '',
  `srcport` int(10) unsigned NOT NULL DEFAULT '0',
  `dstport` int(10) unsigned NOT NULL DEFAULT '0',
  `protocol` varchar(128) NOT NULL DEFAULT '',
  `payload_printable` varchar(2048) NOT NULL DEFAULT '',
  `action` varchar(128) NOT NULL DEFAULT '',
  `gid` int(10) unsigned NOT NULL DEFAULT '0',
  `signature_id` int(10) unsigned NOT NULL DEFAULT '0',
  `rev` int(10) unsigned NOT NULL DEFAULT '0',
  `signature` varchar(1024) NOT NULL DEFAULT '',
  `category` varchar(256) NOT NULL DEFAULT '',
  `severity` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `ossec_events` (
  `event_id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `probe_id` varchar(128) NOT NULL DEFAULT '',
  `time_of_event` datetime DEFAULT NULL,
  `level` int(10) unsigned NOT NULL DEFAULT '0',
  `sidid` int(10) unsigned NOT NULL DEFAULT '0',
  `comment` varchar(1024) NOT NULL DEFAULT '',
  `group_name` varchar(256) NOT NULL DEFAULT '',
  `cve` varchar(256) NOT NULL DEFAULT '',
  `info` varchar(256) NOT NULL DEFAULT '',
  `full_log` varchar(2048) NOT NULL DEFAULT '',
  `hostname` varchar(128) NOT NULL DEFAULT '',
  `location` varchar(256) NOT NULL DEFAULT '',
  `srcip` varchar(32) NOT NULL DEFAULT '',
  `dstip` varchar(32) NOT NULL DEFAULT '',
  `srcport` int(10) unsigned NOT NULL DEFAULT '0',
  `dstport` int(10) unsigned NOT NULL DEFAULT '0',
  `protocol` varchar(128) NOT NULL DEFAULT '',
  `action` varchar(256) NOT NULL DEFAULT '',
  `srcuser` varchar(128) NOT NULL DEFAULT '',
  `dstuser` varchar(128) NOT NULL DEFAULT '',
  `filename` varchar(256) NOT NULL DEFAULT '',
  `md5_before` varchar(256) NOT NULL DEFAULT '',
  `md5_after` varchar(256) NOT NULL DEFAULT '',
  `sha1_before` varchar(256) NOT NULL DEFAULT '',
  `sha1_after` varchar(256) NOT NULL DEFAULT '',
  `owner_before` varchar(256) NOT NULL DEFAULT '',
  `owner_after` varchar(256) NOT NULL DEFAULT '',
  `gowner_before` varchar(256) NOT NULL DEFAULT '',
  `gowner_after` varchar(256) NOT NULL DEFAULT '',
  PRIMARY KEY (`event_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;










