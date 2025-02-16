use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{fs, thread};

use anyhow::Result;
use cedar_policy::{Authorizer, Decision, Entities, PolicySet, Response};

/// A trait for types that provide access to a cedar PolicySet
pub trait PolicyStore: Send + Sync {
    /// Returns whether the initial policy load is complete
    /// While this is false, the authorizer should emit a "no opinion" response
    fn initial_policy_load_complete(&self) -> bool;

    /// Returns a reference to the PolicySet
    fn policy_set(&self) -> &PolicySet;

    /// Returns the name of the policy store
    fn name(&self) -> &str;
}

/// An in-memory policy store that is immutable and can be configured to be ready or not
pub struct MemoryStore {
    policies: PolicySet,
    load_complete: bool,
    name: String,
}

impl MemoryStore {
    /// Creates a new MemoryStore from a policy document
    ///
    /// # Arguments
    /// * `name` - Name of the policy store/file
    /// * `document` - The policy document as bytes
    /// * `load_complete` - Whether the store should be considered ready
    ///
    /// # Returns
    /// A Result containing the new MemoryStore or an error if the policy document is invalid
    pub fn new(name: impl Into<String>, document: &str, load_complete: bool) -> Result<Self> {
        let policies = PolicySet::from_str(document)?;
        Ok(Self {
            policies,
            load_complete,
            name: name.into(),
        })
    }
}

impl PolicyStore for MemoryStore {
    fn initial_policy_load_complete(&self) -> bool {
        self.load_complete
    }

    fn policy_set(&self) -> &PolicySet {
        &self.policies
    }

    fn name(&self) -> &str {
        &self.name
    }
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

    fn policy_set(&self) -> &PolicySet {
        &self.0
    }

    fn name(&self) -> &str {
        "StaticStore"
    }
}

/// A policy store that loads policies from a directory
pub struct DirectoryStore {
    // TODO: thread locking?
    policies: Arc<RwLock<PolicySet>>,
}

impl DirectoryStore {
    /// Creates a new DirectoryStore
    pub fn new(directory: impl AsRef<Path>, refresh_interval: Duration) -> Self {
        let store = Self {
            // directory: directory.as_ref().to_path_buf(),
            policies: Arc::new(RwLock::new(PolicySet::new())),
        };
        store.load_policies(directory.as_ref());

        // Start background refresh
        let policies = store.policies.clone();
        let dir = directory.as_ref().to_path_buf();
        thread::spawn(move || loop {
            thread::sleep(refresh_interval);
            Self::load_policies_into(&dir, &policies);
        });

        store
    }

    fn load_policies(&self, directory: &Path) {
        Self::load_policies_into(directory, &self.policies);
    }

    fn load_policies_into(directory: &Path, policies: &RwLock<PolicySet>) {
        let mut policy_set = PolicySet::new();

        if let Ok(entries) = fs::read_dir(directory) {
            for entry in entries.flatten() {
                let path = entry.path();

                // Skip non-regular files and non-.cedar files
                if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("cedar") {
                    continue;
                }

                if let Ok(data) = fs::read_to_string(&path) {
                    if let Ok(policies) = PolicySet::from_str(&data) {
                        // TODO: We need to properly handle multiple policies in a file
                        // This is a temporary solution that just replaces the entire set
                        policy_set = policies;
                    }
                }
            }
        }

        if let Ok(mut policies) = policies.write() {
            *policies = policy_set;
        }
    }
}

#[derive(Clone)]
struct PolicySetRef(Arc<RwLock<PolicySet>>);

impl PolicyStore for DirectoryStore {
    fn initial_policy_load_complete(&self) -> bool {
        true
    }

    fn policy_set(&self) -> &PolicySet {
        // This is safe because we know the lock exists for the lifetime of self
        unsafe {
            let guard = self.policies.read().unwrap();
            std::mem::transmute::<&PolicySet, &PolicySet>(&*guard)
        }
    }

    fn name(&self) -> &str {
        "FilePolicyStore"
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
    pub fn is_authorized(&self, entities: &Entities, request: &cedar_policy::Request) -> Response {
        let authorizer = Authorizer::new();

        for (i, store) in self.stores.iter().enumerate() {
            let response = authorizer.is_authorized(request, store.policy_set(), entities);
            let diagnostics = response.diagnostics();

            // If this is the last store, return its decision regardless
            if i == self.stores.len() - 1 {
                return response;
            }

            // If we got a Deny with no reasons or errors, continue to next store
            if response.decision() == Decision::Deny
                && diagnostics.errors().count() == 0
                && diagnostics.reason().count() == 0
            {
                continue;
            }

            // Otherwise return this store's decision
            return response;
        }

        // This should never happen as we always return in the last iteration
        unreachable!("TieredPolicyStores had no stores")
    }
}
