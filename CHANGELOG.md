<!-- markdownlint-disable-file MD041 -->
## upcoming release

## 1.2.1 (May 23, 2022)

BUG FIXES:

* resource/`iptabes_nat`,`iptables_nat_ipv6`: fix reading nat blocks when a member of an on_cidr_blocks list is ok, but a previous member doesn't have all the snat/dnat rules
* resource/`iptables_rules`,`iptables_rules_ipv6`: fix reading gress blocks when a member of an on_cidr_blocks list is ok, but a previous member doesn't have all the ingress/egress rules

PATCH:

* minor refactoring to fix linters errors

## 1.2.0 (July 30, 2021)

* switch to the standalone SDK v2 for compatibility with last Terraform version
* move docs in dedicated directory
* bump golang version
* refactor release workflow (GH Actions) to generate files compatible with Terraform registry

## 1.1.2 (July 06, 2021)

* fix permanent conflict between `vault_enable` and `login`/`password` provider arguments

## 1.1.1 (March 13, 2020)

* fix crash when add/modify iptables_project_ipv6 with position

## 1.1.0 (December 05, 2019)

* add an option to not add default drop

## 1.0.2 (December 05, 2019)

* fix read with position on raw/nat/filter

## 1.0.1 (October 10, 2019)

* Position check + rewrite TypeList to TypeSet

## 1.0.0 (August 31, 2019)

First release
