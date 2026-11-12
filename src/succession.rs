//! Finds, for each disabled manager, the first enabled account above them in
//! the reporting line: a suggestion for whom their people could report to
//! instead. It is derived from the directory, not stored in it, and says
//! nothing about whether that person is a suitable manager.

use std::collections::{BTreeSet, HashMap, HashSet};

use tokio::task::JoinSet;

use crate::error::{EntraError, Result};
use crate::graph::GraphClient;
use crate::model::{ManagedUser, ManagerSummary};

/// The longest walk up from one disabled manager, matching `user chain`.
const MAXIMUM_LEVELS: usize = 10;

/// The most manager lookups in flight at once.
const CONCURRENT_LOOKUPS: usize = 8;

/// Each person's manager by object id, `None` when the directory records
/// none. Seeded from the listing the check already holds, so only people the
/// listing left out cost a request.
type ManagerLinks = HashMap<String, Option<ManagerSummary>>;

enum Walk {
    Found(Option<ManagerSummary>),
    Missing(String),
}

/// Fills `next_enabled_manager` on every row, reading only the manager links
/// that `listing` does not already hold.
pub async fn fill_next_enabled_managers(
    graph: &GraphClient,
    listing: &[ManagedUser],
    rows: &mut [ManagedUser],
) -> Result<()> {
    let mut links: ManagerLinks = listing
        .iter()
        .filter(|person| !person.user.id.is_empty())
        .map(|person| (person.user.id.clone(), person.manager.clone()))
        .collect();
    let starts: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row.manager.as_ref().map(|manager| manager.id.clone()))
        .collect();
    let found = walk_all(graph, &mut links, &starts).await?;
    for row in rows {
        let next = row
            .manager
            .as_ref()
            .and_then(|manager| found.get(&manager.id).cloned().flatten());
        // A loop in the reporting line can lead back to the person; never
        // suggest that someone report to themself.
        row.next_enabled_manager = next.filter(|next| next.id != row.user.id);
    }
    Ok(())
}

/// Walks up from every start, fetching each round's missing links together,
/// until every walk has an answer.
async fn walk_all(
    graph: &GraphClient,
    links: &mut ManagerLinks,
    starts: &BTreeSet<String>,
) -> Result<HashMap<String, Option<ManagerSummary>>> {
    let mut found = HashMap::new();
    loop {
        let mut missing = BTreeSet::new();
        for start in starts {
            if found.contains_key(start) {
                continue;
            }
            match walk(links, start)? {
                Walk::Found(next) => {
                    found.insert(start.clone(), next);
                }
                Walk::Missing(id) => {
                    missing.insert(id);
                }
            }
        }
        if missing.is_empty() {
            return Ok(found);
        }
        fetch_links(graph, links, missing).await?;
    }
}

/// Follows `links` up from `start` to the first manager whose account is
/// enabled. Stops with no answer at the top of the line, at a manager whose
/// enabled state is unknown, at a loop, or after `MAXIMUM_LEVELS`. Returns
/// the first id whose manager is not yet known, so the caller can fetch it.
fn walk(links: &ManagerLinks, start: &str) -> Result<Walk> {
    let mut seen = HashSet::from([start.to_owned()]);
    let mut current = start.to_owned();
    for _ in 0..MAXIMUM_LEVELS {
        let Some(link) = links.get(&current) else {
            return Ok(Walk::Missing(current));
        };
        let Some(manager) = link else {
            return Ok(Walk::Found(None));
        };
        if manager.id.is_empty() {
            return Err(EntraError::message(
                "Graph returned a manager without an object id, so the reporting line cannot be followed",
            ));
        }
        match manager.account_enabled {
            Some(true) => return Ok(Walk::Found(Some(manager.clone()))),
            None => return Ok(Walk::Found(None)),
            Some(false) => {}
        }
        if !seen.insert(manager.id.clone()) {
            return Ok(Walk::Found(None));
        }
        current = manager.id.clone();
    }
    Ok(Walk::Found(None))
}

/// Reads the manager of every id in `missing`, at most `CONCURRENT_LOOKUPS`
/// at a time, into `links`. The first failure stops the rest.
async fn fetch_links(
    graph: &GraphClient,
    links: &mut ManagerLinks,
    missing: BTreeSet<String>,
) -> Result<()> {
    let mut pending = missing.into_iter();
    let mut running = JoinSet::new();
    loop {
        while running.len() < CONCURRENT_LOOKUPS {
            let Some(id) = pending.next() else { break };
            let graph = graph.clone();
            running.spawn(async move {
                let manager = graph.manager_of_object(&id).await;
                (id, manager)
            });
        }
        let Some(joined) = running.join_next().await else {
            return Ok(());
        };
        let (id, manager) = joined
            .map_err(|error| EntraError::message(format!("manager lookup failed: {error}")))?;
        links.insert(id, manager?.map(ManagerSummary::from));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(id: &str, enabled: Option<bool>) -> ManagerSummary {
        ManagerSummary {
            id: id.into(),
            display_name: format!("Person {id}"),
            user_principal_name: format!("{id}@example.test"),
            account_enabled: enabled,
        }
    }

    fn links(entries: &[(&str, Option<ManagerSummary>)]) -> ManagerLinks {
        entries
            .iter()
            .map(|(id, manager)| ((*id).to_owned(), manager.clone()))
            .collect()
    }

    fn found(walk: Walk) -> Option<String> {
        match walk {
            Walk::Found(next) => next.map(|manager| manager.id),
            Walk::Missing(id) => panic!("walk wanted {id}"),
        }
    }

    #[test]
    fn walk_skips_disabled_managers_to_the_first_enabled_one() {
        let links = links(&[
            ("a", Some(summary("b", Some(false)))),
            ("b", Some(summary("c", Some(true)))),
        ]);
        assert_eq!(found(walk(&links, "a").unwrap()), Some("c".into()));
    }

    #[test]
    fn walk_stops_without_an_answer_at_the_top_an_unknown_state_or_a_loop() {
        let top = links(&[("a", None)]);
        assert_eq!(found(walk(&top, "a").unwrap()), None);
        let unknown = links(&[("a", Some(summary("b", None)))]);
        assert_eq!(found(walk(&unknown, "a").unwrap()), None);
        let looped = links(&[
            ("a", Some(summary("b", Some(false)))),
            ("b", Some(summary("a", Some(false)))),
        ]);
        assert_eq!(found(walk(&looped, "a").unwrap()), None);
    }

    #[test]
    fn walk_asks_for_the_first_link_it_does_not_hold() {
        let links = links(&[("a", Some(summary("b", Some(false))))]);
        match walk(&links, "a").unwrap() {
            Walk::Missing(id) => assert_eq!(id, "b"),
            Walk::Found(_) => panic!("walk should need b's manager"),
        }
    }

    #[test]
    fn walk_refuses_a_manager_without_an_object_id() {
        let links = links(&[("a", Some(summary("", Some(true))))]);
        assert!(walk(&links, "a").is_err());
    }

    #[test]
    fn walk_gives_up_after_the_level_limit() {
        let entries: Vec<(String, Option<ManagerSummary>)> = (0..=MAXIMUM_LEVELS)
            .map(|level| {
                (
                    format!("p{level}"),
                    Some(summary(&format!("p{}", level + 1), Some(false))),
                )
            })
            .collect();
        let links: ManagerLinks = entries.into_iter().collect();
        assert_eq!(found(walk(&links, "p0").unwrap()), None);
    }
}
