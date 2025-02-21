use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, thread};
use uuid::Uuid;

use anyhow::Result;
use cedar_policy::{Authorizer, Decision, Entities, Policy, PolicyId, PolicySet, Response};
use parking_lot::RwLock;

/// A trait for types that provide access to a cedar PolicySet
pub trait PolicyStore: Send + Sync {
    /// Returns whether the initial policy load is complete
    /// While this is false, the authorizer should emit a "no opinion" response
    fn initial_policy_load_complete(&self) -> bool;

    /// Returns a reference to the PolicySet
    fn policy_set(&self) -> Result<PolicySet>;

    /// Returns the name of the policy store
    fn name(&self) -> &str;
}

/// A static store that wraps a PolicySet directly
#[derive(Clone)]
pub struct StaticStore(PolicySet);

impl From<PolicySet> for StaticStore {
    fn from(policy_set: PolicySet) -> Self {
        Self(policy_set)
    }
}

impl PolicyStore for StaticStore {
    fn initial_policy_load_complete(&self) -> bool {
        true
    }

    fn policy_set(&self) -> Result<PolicySet> {
        Ok(self.0.clone())
    }

    fn name(&self) -> &str {
        "StaticStore"
    }
}

/// A policy store that loads policies from a directory
#[derive(Clone)]
pub struct DirectoryStore {
    policies: Arc<RwLock<PolicySet>>,
    name: String,
}

impl DirectoryStore {
    /// Creates a new DirectoryStore
    pub fn new(directory: impl AsRef<Path>, refresh_interval: Duration) -> Result<Self> {
        if refresh_interval.is_zero() {
            return Err(anyhow::anyhow!("Refresh interval must be greater than 0"));
        }
        if refresh_interval < Duration::from_secs(1) {
            return Err(anyhow::anyhow!("Refresh interval must be at least 1 second"));
        }
        

        let dir_path = directory.as_ref().to_path_buf();
        let store = Self {
            policies: Arc::new(RwLock::new(PolicySet::new())),
            name: format!("DirectoryStore ({})", dir_path.display()),
        };
        store.load_policies(&dir_path)?;

        // Start background refresh
        let policies = store.clone().policies.clone();
        let dir = dir_path;
        let cloned_store = store.clone();
        thread::spawn(move || loop {
            thread::sleep(refresh_interval);
            match Self::load_policies_into(&dir, &policies) {
                Ok(_) => (),
                Err(e) => log::error!("Error loading policies into store {}({}): {}", store.name, dir.display(), e),
            }
        });

        Ok(cloned_store)
    }

    fn load_policies(&self, directory: &Path) -> Result<()> {
        Self::load_policies_into(directory, &self.policies)
    }

    fn load_policies_into(directory: &Path, policies: &RwLock<PolicySet>) -> Result<()> {
        let mut pvec: Vec<Policy> = Vec::new();

        if let Ok(entries) = fs::read_dir(directory) {
            for entry in entries.flatten() {
                let path = entry.path();

                // Skip non-regular files and non-.cedar files
                if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("cedar") {
                    continue;
                }

                if let Ok(data) = fs::read_to_string(&path) {
                    let local_pset: PolicySet = data.parse()?;
                    // Parse each policy individually instead of as a PolicySet
                    for policy in local_pset.policies() {
                        //  use the `id` annotation or make a random string
                        let id = match policy.annotation("id") {
                            Some(id) => id.to_string(),
                            None => Uuid::new_v4().to_string(),
                        };
                        pvec.push(policy.new_id(PolicyId::new(id)));
                    }
                }
            }
        }
        log::debug!("DirectoryStore ({}) loaded {} policies", directory.display(), pvec.len());
        let pset = PolicySet::from_policies(pvec)?;
        *policies.write() = pset;
        Ok(())
    }
}

impl PolicyStore for DirectoryStore {
    fn initial_policy_load_complete(&self) -> bool {
        true
    }

    fn policy_set(&self) -> Result<PolicySet> {
        Ok(self.policies.read().clone())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// A collection of PolicyStores that are checked in sequence until an explicit decision is found
pub struct TieredPolicyStores<'a> {
    stores: Vec<Box<dyn PolicyStore + 'a>>,
}

impl<'a> TieredPolicyStores<'a> {
    /// Creates a new TieredPolicyStores
    pub fn new(stores: Vec<Box<dyn PolicyStore + 'a>>) -> Self {
        Self { stores }
    }

    /// Checks each policy store in sequence for an explicit decision.
    /// If no explicit decision is found in a store, it continues to the next store.
    /// If no explicit decision is found in the last store, that store's decision (deny) is returned.
    pub fn is_authorized(&self, entities: &Entities, request: &cedar_policy::Request) -> Result<Response> {
        let authorizer = Authorizer::new();

        for (i, store) in self.stores.iter().enumerate() {
            let pset = store.policy_set()?;
            let response = authorizer.is_authorized(request, &pset, entities);
            let diagnostics = response.diagnostics();

            // print a debug log for the response
            log::debug!("Store {} response: {:?}", store.name(), response);

            // If this is the last store, return its decision regardless
            if i == self.stores.len() - 1 {
                return Ok(response);
            }

            // If we got a Deny with no reasons or errors, continue to next store
            if response.decision() == Decision::Deny
                && diagnostics.errors().count() == 0
                && diagnostics.reason().count() == 0
            {
                continue;
            }

            // Otherwise return this store's decision
            return Ok(response);
        }

        // This should never happen as we always return in the last iteration
        unreachable!("TieredPolicyStores had no stores")
    }
}
