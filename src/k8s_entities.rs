use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::{anyhow, Result};
use cedar_policy::{
    Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
    Schema,
};
use k8s_openapi::api::authorization::v1::SubjectAccessReview;

use crate::k8s_resource::{
    create_resource_entity, ACTION_TYPE, GROUP_TYPE, NODE_TYPE, SERVICE_ACCOUNT_TYPE, USER_TYPE,
};

/// Represents the different types of entities in our system
#[derive(Debug)]
pub enum EntityType {
    User,
    Node,
    ServiceAccount,
    Group,
}

impl EntityType {
    fn as_str(&self) -> &'static str {
        match self {
            EntityType::User => USER_TYPE,
            EntityType::Node => NODE_TYPE,
            EntityType::ServiceAccount => SERVICE_ACCOUNT_TYPE,
            EntityType::Group => GROUP_TYPE,
        }
    }
}

#[derive(Debug)]
pub enum ActionType {
    Approve,
    Attest,
    Bind,
    Create,
    Delete,
    DeleteCollection,
    Escalate,
    Get,
    Head,
    Impersonate,
    List,
    Options,
    Patch,
    Post,
    Put,
    ReadOnly,
    Sign,
    Update,
    Use,
    Watch,
}

impl ActionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionType::Approve => "approve",
            ActionType::Attest => "attest",
            ActionType::Bind => "bind",
            ActionType::Create => "create",
            ActionType::Delete => "delete",
            ActionType::DeleteCollection => "deletecollection",
            ActionType::Escalate => "escalate",
            ActionType::Get => "get",
            ActionType::Head => "head",
            ActionType::Impersonate => "impersonate",
            ActionType::List => "list",
            ActionType::Options => "options",
            ActionType::Patch => "patch",
            ActionType::Post => "post",
            ActionType::Put => "put",
            ActionType::ReadOnly => "readOnly",
            ActionType::Sign => "sign",
            ActionType::Update => "update",
            ActionType::Use => "use",
            ActionType::Watch => "watch",
        }
    }
}

/// Creates a Cedar EntityUid with proper namespace
pub fn create_entity_uid(entity_type: EntityType, id: &str) -> Result<EntityUid> {
    let type_name = EntityTypeName::from_str(entity_type.as_str())?;
    let entity_id = EntityId::from_str(id)?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

/// Converts a Kubernetes user from a SubjectAccessReview into a Cedar Entity
pub fn create_user_entity(review: &SubjectAccessReview) -> Result<(Entity, Vec<Entity>)> {
    let username = review.spec.user.as_deref().unwrap_or("anonymous");
    let uid = review.spec.uid.as_deref().unwrap_or(username);

    // Create group entities first
    let mut group_entities = Vec::new();
    let mut group_uids = HashSet::new();

    if let Some(groups) = &review.spec.groups {
        for group in groups {
            let group_uid = create_entity_uid(EntityType::Group, group)?;

            let attrs = HashMap::from([(
                "name".to_string(),
                RestrictedExpression::new_string(group.to_string()),
            )]);
            let group_entity = Entity::new(group_uid.clone(), attrs, HashSet::new())
                .map_err(|e| anyhow!("Failed to create group entity: {}", e))?;

            group_entities.push(group_entity);
            group_uids.insert(group_uid);
        }
    }

    // Determine the principal type and attributes based on the username
    let (principal_type, mut attrs) = if username.starts_with("system:node:")
        && username.matches(':').count() == 2
    {
        let node_name = username
            .split(':')
            .nth(2)
            .ok_or_else(|| anyhow!("Missing node name in username"))?;
        let mut attrs = HashMap::new();
        attrs.insert(
            "name".to_string(),
            RestrictedExpression::new_string(node_name.to_string()),
        );
        (EntityType::Node, attrs)
    } else if username.starts_with("system:serviceaccount:") && username.matches(':').count() == 3 {
        let parts: Vec<&str> = username.split(':').collect();
        let mut attrs = HashMap::new();
        attrs.insert(
            "namespace".to_string(),
            RestrictedExpression::new_string(
                parts
                    .get(2)
                    .ok_or_else(|| anyhow!("Missing namespace in service account name"))?
                    .to_string(),
            ),
        );
        attrs.insert(
            "name".to_string(),
            RestrictedExpression::new_string(
                parts
                    .get(3)
                    .ok_or_else(|| anyhow!("Missing name in service account name"))?
                    .to_string(),
            ),
        );
        (EntityType::ServiceAccount, attrs)
    } else {
        let mut attrs = HashMap::new();
        attrs.insert(
            "name".to_string(),
            RestrictedExpression::new_string(username.to_string()),
        );
        (EntityType::User, attrs)
    };

    // Add extra fields if present
    if let Some(extra) = &review.spec.extra {
        let mut extra_values = Vec::new();
        for (k, v) in extra {
            let extra_value = v
                .iter()
                .map(|val| val.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let record = RestrictedExpression::new_record(HashMap::from([
                (
                    "key".to_string(),
                    RestrictedExpression::new_string(k.to_string()),
                ),
                (
                    "values".to_string(),
                    RestrictedExpression::new_string(extra_value),
                ),
            ]))
            .map_err(|e| anyhow!("Failed to create extra record: {}", e))?;
            extra_values.push(record);
        }

        if !extra_values.is_empty() {
            attrs.insert(
                "extra".to_string(),
                RestrictedExpression::new_set(extra_values),
            );
        }
    }

    let principal_uid = create_entity_uid(principal_type, uid)?;

    let principal_entity = Entity::new(principal_uid, attrs, group_uids)
        .map_err(|e| anyhow!("Failed to create principal entity: {}", e))?;

    Ok((principal_entity, group_entities))
}

/// Converts a Kubernetes action (verb) from a SubjectAccessReview into a Cedar Entity
pub fn create_action_entity(review: &SubjectAccessReview) -> Result<Entity> {
    let verb = review
        .spec
        .resource_attributes
        .as_ref()
        .and_then(|attrs| attrs.verb.as_deref())
        .unwrap_or("unknown");

    let uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(ACTION_TYPE)?,
        EntityId::from_str(verb)?,
    );

    Entity::new(uid, HashMap::new(), HashSet::new())
        .map_err(|e| anyhow!("Failed to create action entity: {}", e))
}

/// Creates all entities needed for authorization from a SubjectAccessReview
pub fn create_entities_and_request(
    review: &SubjectAccessReview,
    schema: Option<&Schema>,
) -> Result<(Entities, Request)> {
    // Create each entity and collect them
    let (user, groups) = create_user_entity(review)?;
    let action = create_action_entity(review)?;
    let resource = create_resource_entity(review)?;

    // Create a new Entities collection with our entities
    let mut entity_set = Vec::new();
    entity_set.push(user.clone());
    entity_set.extend(groups);
    entity_set.push(action.clone());
    entity_set.push(resource.clone());

    let request = Request::new(
        Some(user.uid()),
        Some(action.uid()),
        Some(resource.uid()),
        Context::empty(),
        schema,
    )
    .map_err(|e| anyhow!("Failed to create request: {}", e))?;

    Ok((Entities::from_entities(entity_set, schema)?, request))
}
