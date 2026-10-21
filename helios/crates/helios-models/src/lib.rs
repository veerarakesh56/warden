//! Per-resource availability models.
//!
//! Each AWS resource kind we support has a canonical failure footprint. An EC2 instance
//! lives in exactly one AZ; an RDS with `multi_az = true` spans two; an S3 bucket is
//! regional. These are hand-authored, not inferred, because the correctness of the whole
//! simulator depends on them. Contributions welcome — see CONTRIBUTING.md.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ops::Range;

pub type Region = String;
pub type Az = String;

/// How a resource survives failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvailabilityModel {
    /// Lives in exactly one AZ. Fails if that AZ fails.
    SingleAz { az: Az },
    /// Spans multiple AZs with a defined failover time window.
    MultiAz {
        azs: Vec<Az>,
        #[serde(with = "range_ser")]
        failover_seconds: Range<u32>,
    },
    /// Regional control plane. Fails only if the whole region fails.
    Regional { region: Region },
    /// Global edge (Route53, CloudFront). Only a full-provider outage affects it.
    GlobalEdge,
}

/// Infer the availability model for a Terraform resource from its type + attrs.
///
/// `default_region` is the LAST resort. The region is derived per resource by [`region_for`] —
/// an explicit `region`, the zone it declares, the first zone it spans, or the region field of an
/// ARN it carries — because `terraform show -json` does not carry the provider's region. Callers
/// should pass [`infer_region`] over the whole graph as the default, so the handful of resources
/// with no region signal at all land in the region everything else agrees on rather than in
/// `us-east-1`.
pub fn availability_for(tf_type: &str, attrs: &Value, default_region: &str) -> AvailabilityModel {
    match tf_type {
        "aws_vpc" => AvailabilityModel::Regional {
            region: region_of(attrs, default_region),
        },
        "aws_subnet" => AvailabilityModel::SingleAz {
            az: string_attr(attrs, "availability_zone")
                .unwrap_or_else(|| format!("{}a", region_for(attrs, default_region))),
        },
        "aws_instance" => AvailabilityModel::SingleAz {
            az: string_attr(attrs, "availability_zone")
                .unwrap_or_else(|| format!("{}a", region_for(attrs, default_region))),
        },
        "aws_lb" => AvailabilityModel::MultiAz {
            azs: azs_from_subnets(attrs),
            // ALB health-check + DNS propagation — fast.
            failover_seconds: 5..30,
        },
        "aws_db_instance" => {
            let multi_az = attrs
                .get("multi_az")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if multi_az {
                AvailabilityModel::MultiAz {
                    // Terraform does not say WHICH zones a multi-AZ RDS occupies, so the pair is a
                    // guess — but it must be a guess inside the resource's OWN region, which is
                    // derivable. Using the global default here silently placed every non-us-east-1
                    // database in us-east-1, so it survived its real region going down.
                    azs: {
                        let region = region_for(attrs, default_region);
                        vec![format!("{region}a"), format!("{region}b")]
                    },
                    // RDS published failover window.
                    failover_seconds: 30..120,
                }
            } else {
                AvailabilityModel::SingleAz {
                    az: string_attr(attrs, "availability_zone")
                        .unwrap_or_else(|| format!("{}a", region_for(attrs, default_region))),
                }
            }
        }
        "aws_elasticache_cluster" => {
            // One node. Replication is an aws_elasticache_replication_group, its own kind
            // (spread over its members); a plain cluster is SingleAz.
            AvailabilityModel::SingleAz {
                az: string_attr(attrs, "availability_zone")
                    .unwrap_or_else(|| format!("{default_region}a")),
            }
        }
        "aws_lambda_function" => {
            // Lambda is a regional service. If vpc_config.subnet_ids spans multiple AZs,
            // cold-starts can still run in any of them, but the failure surface is regional.
            AvailabilityModel::Regional {
                region: region_of(attrs, default_region),
            }
        }
        "aws_s3_bucket" => AvailabilityModel::Regional {
            region: region_of(attrs, default_region),
        },
        // An Aurora instance lives in one zone -- but Terraform only knows which after apply. With
        // no zone it is Regional here and its subnet-group spread decides (see `spread_rule`).
        "aws_rds_cluster_instance" => match string_attr(attrs, "availability_zone") {
            Some(az) => AvailabilityModel::SingleAz { az },
            None => AvailabilityModel::Regional {
                region: region_for(attrs, default_region),
            },
        },
        // Everything else, including the 0.2 kinds (RDS/ElastiCache clusters, ECS, EKS, SQS, VPC
        // endpoints, NAT gateways), is Regional: its zonal exposure comes from its graph edges
        // (Contains / Spread), not from a zone attribute.
        _ => AvailabilityModel::Regional {
            region: region_for(attrs, default_region),
        },
    }
}

/// How a resource with `Spread` edges (a placement group: the subnets an ECS service runs in, the
/// instances of an Aurora cluster) survives losing members of that group. Read from the attrs at
/// SOLVE time, not graph-build time, so a `set_attr` fix such as `desired_count = 2` re-verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpreadRule {
    /// The group does not decide availability (the zone is known and modelled directly).
    Ignore,
    /// Up while any member is up: capacity >= 2 spread across the members.
    AnySurvivor,
    /// Capacity 1, or placement unknown until apply: assume the worst -- down when any member is.
    FailsIfAnyDown,
}

/// The [`SpreadRule`] for a resource of `tf_type` with these attrs.
pub fn spread_rule(tf_type: &str, attrs: &Value) -> SpreadRule {
    use SpreadRule::*;
    let at_least = |path: &[&str], n: u64| number_at(attrs, path).is_some_and(|v| v >= n);
    match tf_type {
        "aws_rds_cluster_instance" => {
            if string_attr(attrs, "availability_zone").is_some() {
                Ignore
            } else {
                FailsIfAnyDown
            }
        }
        "aws_elasticache_replication_group" => {
            let failover = attrs
                .get("automatic_failover_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if failover
                && (at_least(&["num_cache_clusters"], 2)
                    || at_least(&["replicas_per_node_group"], 1))
            {
                AnySurvivor
            } else {
                FailsIfAnyDown
            }
        }
        "aws_ecs_service" if !at_least(&["desired_count"], 2) => FailsIfAnyDown,
        "aws_eks_node_group" if !at_least(&["scaling_config", "desired_size"], 2) => FailsIfAnyDown,
        // aws_rds_cluster (over its instances), interface VPC endpoints, and a satisfied ECS / EKS
        // capacity: up while any member is.
        _ => AnySurvivor,
    }
}

/// A number at `path`, stepping into the first element of a list of blocks (`scaling_config[0]`).
fn number_at(attrs: &Value, path: &[&str]) -> Option<u64> {
    let mut v = attrs;
    for seg in path {
        if let Value::Array(items) = v {
            v = items.first()?;
        }
        v = v.get(seg)?;
    }
    v.as_u64()
}

/// Would [`availability_for`] have to GUESS this resource's zone? A kind modelled by its own
/// `availability_zone` that does not declare one is placed in the region's `a` zone -- a guess, so
/// no zone-outage verdict about it can be trusted.
pub fn zone_is_guessed(tf_type: &str, attrs: &Value) -> bool {
    let known = string_attr(attrs, "availability_zone").is_some_and(|z| !z.is_empty());
    let multi_az = attrs.get("multi_az").and_then(Value::as_bool) == Some(true);
    match tf_type {
        "aws_subnet" | "aws_instance" | "aws_elasticache_cluster" => !known,
        "aws_db_instance" => !known && !multi_az,
        _ => false,
    }
}

/// Strip the trailing zone letter from an AZ id: `eu-west-2a` -> `eu-west-2`.
///
/// The region is everything up to the first `-`-separated part that starts with a digit, that
/// part's digits included -- so a Local Zone (`us-west-2-lax-1a`) and a Wavelength Zone
/// (`us-east-1-wl1-bos-wlz-1`) map to their PARENT region (`us-west-2`, `us-east-1`), whose outage
/// takes them down. Anything else: the input with one trailing letter stripped.
pub fn region_of_az(az: &str) -> Region {
    let parts: Vec<&str> = az.split('-').collect();
    if let Some(i) = parts
        .iter()
        .position(|p| p.starts_with(|c: char| c.is_ascii_digit()))
    {
        let digits: String = parts[i].chars().take_while(char::is_ascii_digit).collect();
        if i >= 2 {
            return format!("{}-{digits}", parts[..i].join("-"));
        }
    }
    if az
        .as_bytes()
        .last()
        .map(|c| c.is_ascii_alphabetic())
        .unwrap_or(false)
    {
        az[..az.len() - 1].to_string()
    } else {
        az.to_string()
    }
}

/// A region name: `<area>-<name>-<number>` (`eu-west-2`), possibly with more name parts
/// (`us-gov-west-1`).
pub fn well_formed_region(region: &str) -> bool {
    let parts: Vec<&str> = region.split('-').collect();
    let (last, names) = parts.split_last().expect("split yields at least one part");
    parts.len() >= 3
        && names
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
        && !last.is_empty()
        && last.chars().all(|c| c.is_ascii_digit())
}

/// A zone name: `<region><letter>` (`eu-west-2a`), or a Local / Wavelength Zone -- the parent
/// region, then `-` and lowercase-alphanumeric parts (`us-west-2-lax-1a`,
/// `us-east-1-wl1-bos-wlz-1`).
pub fn well_formed_zone(az: &str) -> bool {
    let region = region_of_az(az);
    if !well_formed_region(&region) || !az.starts_with(&region) {
        return false;
    }
    let rest = &az[region.len()..];
    let letter = rest.len() == 1 && rest.chars().all(|c| c.is_ascii_lowercase());
    let extended = rest.len() > 1
        && rest.starts_with('-')
        && rest[1..].split('-').all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
    letter || extended
}

/// The region field of an ARN: `arn:partition:service:REGION:account:resource`.
///
/// Empty for global services (IAM, S3 bucket ARNs, CloudFront), so an empty field is not a region.
fn region_from_arn(arn: &str) -> Option<Region> {
    let field = arn.split(':').nth(3)?;
    if field.is_empty() || !field.contains('-') {
        return None;
    }
    Some(field.to_string())
}

/// Work out which region a resource is in, from whatever Terraform actually emitted.
///
/// `terraform show -json` does not carry the provider's region, so a hard-coded default put every
/// resource without an explicit `region` attribute in us-east-1 — which silently produced the wrong
/// answer for any other estate. Prefer, in order: an explicit region, the zone it declares, the
/// first zone it spans, the region field of any ARN it carries, then the caller's default.
pub fn region_for(attrs: &Value, default_region: &str) -> Region {
    if let Some(r) = string_attr(attrs, "region") {
        return r;
    }
    if let Some(az) = string_attr(attrs, "availability_zone") {
        return region_of_az(&az);
    }
    if let Some(az) = azs_from_subnets(attrs).first() {
        return region_of_az(az);
    }
    // Any attribute that looks like an ARN. `arn` first, then anything else ending in `_arn`, so
    // the resource's own ARN wins over a reference to something else.
    if let Some(arn) = string_attr(attrs, "arn").and_then(|a| region_from_arn(&a)) {
        return arn;
    }
    if let Some(map) = attrs.as_object() {
        let mut keys: Vec<&String> = map.keys().filter(|k| k.ends_with("_arn")).collect();
        keys.sort();
        for k in keys {
            if let Some(r) = map[k].as_str().and_then(region_from_arn) {
                return r;
            }
        }
    }
    default_region.to_string()
}

/// The region the graph as a whole is in: the one the most resources agree on.
///
/// Some resources carry no region signal at all (in the shipped fixture, the Lambda), so a
/// per-resource rule is not enough on its own. Ties break alphabetically so the answer is stable.
pub fn infer_region<'a>(all_attrs: impl Iterator<Item = &'a Value>) -> Option<Region> {
    let mut counts: std::collections::BTreeMap<Region, usize> = Default::default();
    for attrs in all_attrs {
        // Sentinel that cannot be a real region, so "no signal" never wins the vote.
        let r = region_for(attrs, "\0none");
        if r != "\0none" {
            *counts.entry(r).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
        .map(|(r, _)| r)
}

fn region_of(attrs: &Value, default_region: &str) -> Region {
    region_for(attrs, default_region)
}

fn string_attr(attrs: &Value, key: &str) -> Option<String> {
    attrs
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn azs_from_subnets(attrs: &Value) -> Vec<Az> {
    if let Some(azs) = attrs.get("availability_zones").and_then(|v| v.as_array()) {
        return azs
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
    }
    Vec::new()
}

mod range_ser {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::ops::Range;

    #[derive(Serialize, Deserialize)]
    struct Pair {
        start: u32,
        end: u32,
    }

    pub fn serialize<S: Serializer>(r: &Range<u32>, s: S) -> Result<S::Ok, S::Error> {
        Pair {
            start: r.start,
            end: r.end,
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Range<u32>, D::Error> {
        let p = Pair::deserialize(d)?;
        Ok(p.start..p.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const REGION: &str = "us-east-1";

    #[test]
    fn vpc_is_regional() {
        let m = availability_for("aws_vpc", &json!({}), REGION);
        assert_eq!(
            m,
            AvailabilityModel::Regional {
                region: REGION.into()
            }
        );
    }

    #[test]
    fn subnet_is_single_az() {
        let m = availability_for(
            "aws_subnet",
            &json!({"availability_zone": "us-east-1b"}),
            REGION,
        );
        assert_eq!(
            m,
            AvailabilityModel::SingleAz {
                az: "us-east-1b".into()
            }
        );
    }

    #[test]
    fn rds_multi_az() {
        let m = availability_for("aws_db_instance", &json!({"multi_az": true}), REGION);
        assert!(matches!(m, AvailabilityModel::MultiAz { .. }));
    }

    #[test]
    fn rds_single_az_when_multi_az_false() {
        let m = availability_for(
            "aws_db_instance",
            &json!({"multi_az": false, "availability_zone": "us-east-1c"}),
            REGION,
        );
        assert_eq!(
            m,
            AvailabilityModel::SingleAz {
                az: "us-east-1c".into()
            }
        );
    }

    #[test]
    fn elasticache_single_az_by_default() {
        let m = availability_for(
            "aws_elasticache_cluster",
            &json!({"availability_zone": "us-east-1a"}),
            REGION,
        );
        assert_eq!(
            m,
            AvailabilityModel::SingleAz {
                az: "us-east-1a".into()
            }
        );
    }

    #[test]
    fn alb_is_multi_az() {
        let m = availability_for(
            "aws_lb",
            &json!({"availability_zones": ["us-east-1a", "us-east-1b"]}),
            REGION,
        );
        match m {
            AvailabilityModel::MultiAz { azs, .. } => {
                assert_eq!(
                    azs,
                    vec!["us-east-1a".to_string(), "us-east-1b".to_string()]
                );
            }
            _ => panic!("expected MultiAz"),
        }
    }

    #[test]
    fn s3_is_regional() {
        let m = availability_for("aws_s3_bucket", &json!({"region": "us-east-2"}), REGION);
        assert_eq!(
            m,
            AvailabilityModel::Regional {
                region: "us-east-2".into()
            }
        );
    }

    #[test]
    fn lambda_is_regional() {
        let m = availability_for("aws_lambda_function", &json!({}), REGION);
        assert_eq!(
            m,
            AvailabilityModel::Regional {
                region: REGION.into()
            }
        );
    }

    #[test]
    fn ec2_instance_is_single_az() {
        let m = availability_for(
            "aws_instance",
            &json!({"availability_zone": "us-east-1a"}),
            REGION,
        );
        assert_eq!(
            m,
            AvailabilityModel::SingleAz {
                az: "us-east-1a".into()
            }
        );
    }

    #[test]
    fn spread_rules_follow_capacity_and_zone_knowledge() {
        use SpreadRule::*;
        let r = spread_rule;
        assert_eq!(r("aws_rds_cluster", &json!({})), AnySurvivor);
        assert_eq!(r("aws_rds_cluster_instance", &json!({})), FailsIfAnyDown);
        assert_eq!(
            r(
                "aws_rds_cluster_instance",
                &json!({"availability_zone": "x-1a"})
            ),
            Ignore
        );
        assert_eq!(
            r("aws_ecs_service", &json!({"desired_count": 1})),
            FailsIfAnyDown
        );
        assert_eq!(
            r("aws_ecs_service", &json!({"desired_count": 2})),
            AnySurvivor
        );
        let ng = |n: u64| json!({"scaling_config": [{"desired_size": n}]});
        assert_eq!(r("aws_eks_node_group", &ng(1)), FailsIfAnyDown);
        assert_eq!(r("aws_eks_node_group", &ng(2)), AnySurvivor);
        let rg = |failover: bool, n: u64| json!({"automatic_failover_enabled": failover, "num_cache_clusters": n});
        assert_eq!(
            r("aws_elasticache_replication_group", &rg(true, 2)),
            AnySurvivor
        );
        assert_eq!(
            r("aws_elasticache_replication_group", &rg(false, 2)),
            FailsIfAnyDown
        );
        assert_eq!(
            r("aws_elasticache_replication_group", &rg(true, 1)),
            FailsIfAnyDown
        );
        assert_eq!(
            r(
                "aws_elasticache_replication_group",
                &json!({"automatic_failover_enabled": true, "replicas_per_node_group": 1})
            ),
            AnySurvivor
        );
        assert_eq!(r("aws_vpc_endpoint", &json!({})), AnySurvivor);
    }

    #[test]
    fn zones_map_to_their_parent_region() {
        for (az, region) in [
            ("us-east-1a", "us-east-1"),
            ("eu-west-2c", "eu-west-2"),
            ("us-gov-west-1a", "us-gov-west-1"),
            ("us-west-2-lax-1a", "us-west-2"),
            ("us-east-1-wl1-bos-wlz-1", "us-east-1"),
            ("ap-south-2", "ap-south-2"),
        ] {
            assert_eq!(region_of_az(az), region, "{az}");
        }
        for ok in [
            "us-east-1a",
            "us-gov-west-1b",
            "us-west-2-lax-1a",
            "us-east-1-wl1-bos-wlz-1",
        ] {
            assert!(well_formed_zone(ok), "{ok}");
        }
        for bad in [
            "us-east-1",
            "useast1a",
            "us-east-1ab",
            "us-east-1-",
            "US-EAST-1A",
        ] {
            assert!(!well_formed_zone(bad), "{bad}");
        }
        assert!(well_formed_region("us-gov-west-1") && !well_formed_region("us-east1"));
    }

    #[test]
    fn models_roundtrip_json() {
        let m = AvailabilityModel::MultiAz {
            azs: vec!["us-east-1a".into(), "us-east-1b".into()],
            failover_seconds: 30..90,
        };
        let encoded = serde_json::to_string(&m).unwrap();
        let decoded: AvailabilityModel = serde_json::from_str(&encoded).unwrap();
        assert_eq!(m, decoded);
    }
}
